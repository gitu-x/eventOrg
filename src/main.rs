use axum::{
    Router,
    extract::{Form, State},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::net::SocketAddr;
use tokio::fs;
use time::{Date, format_description};
use tower_http::services::ServeDir;

// --- 1. Constants ---
const DB_CONNECT_ERROR: &str = "Database connection error. Check .env and DB status.";
const SESSION_COOKIE_NAME: &str = "session_user";

// --- 2. Data Structures ---

#[derive(Deserialize, Debug)]
pub struct SignupData {
    pub first_name: String,
    pub last_name: String,
    pub dob: String, // will be parsed to Date
    pub gender: String,
    pub username: String,
    pub password: String,
    pub phone_number: String,
    // FIX: Address Fields: Now separated into 6 columns
    pub address_line1: String,
    pub address_line2: String,
    pub landmark: String,
    pub pincode: String,
    pub city: String,
    pub state: String,
    pub id_proof: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

#[derive(FromRow, Serialize, Debug)]
#[serde(crate = "serde")]
pub struct UserRow {
    pub id: i32,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub date_of_birth: Option<Date>,
    pub gender: Option<String>,
    pub phone_number: Option<String>,
    // FIX: Address Fields: Now separated into 6 columns
    pub address_line1: Option<String>,
    pub address_line2: Option<String>,
    pub landmark: Option<String>,
    pub pincode: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub id_proof: Option<String>,
    pub password: String, // Added to check login
}

// --- 3. Application State Structure ---
#[derive(Clone)]
struct AppState {
    db_pool: PgPool,
}

// --- 4. Handlers ---

// Serves the default static file (index.html) or redirects unauthorized users.
async fn root_handler() -> Redirect {
    Redirect::to("/static/index.html")
}

// Handler for User Sign Up: POST /submit
async fn signup_handler(State(state): State<AppState>, Form(data): Form<SignupData>) -> Response {
    eprintln!("Received Signup Data: {:?}", data);
    let date_format = format_description::parse("[year]-[month]-[day]").unwrap();
    let dob_date = match Date::parse(&data.dob, &date_format) {
        Ok(date) => date,
        Err(e) => {
            eprintln!("Date parsing error: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Html("<h1>Invalid Date Format</h1><p>Please use YYYY-MM-DD format.</p>"),
            ).into_response();
        }
    };

    let password_hash = data.password;

    // FIX: Updated INSERT query to use 6 separate address columns
    let result = sqlx::query!(
        "INSERT INTO users (first_name, last_name, username, password, date_of_birth, gender, phone_number, 
         address_line1, address_line2, landmark, pincode, city, state, id_proof) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        data.first_name,
        data.last_name,
        data.username,
        password_hash,
        dob_date,
        data.gender,
        data.phone_number,
        // New Address Fields
        data.address_line1,
        data.address_line2,
        data.landmark,
        data.pincode,
        data.city,
        data.state,
        data.id_proof
    )
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => Redirect::to("/login").into_response(), // Redirect to login.html after signup
        Err(e) => {
            eprintln!("DB Error during signup: {}", e);
            // Handle unique constraint violation (username already exists)
            if e.to_string()
                .contains("duplicate key value violates unique constraint")
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Html("<h1>Username already exists!</h1><p><a href='/signup'>Try again</a></p>"),
                ).into_response();
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Signup Failed</h1>"),
            ).into_response()
        }
    }
}

// Handler for User Login: POST /login
async fn login_handler(
    State(state): State<AppState>,
    mut cookies: CookieJar,
    Form(data): Form<LoginData>,
) -> Response {
    let user_result = sqlx::query_as!(
        UserRow,
        // FIX: Updated SELECT to match new UserRow fields
        "SELECT id, first_name, last_name, username, date_of_birth, gender, phone_number, 
         address_line1, address_line2, landmark, pincode, city, state, id_proof, password
         FROM users WHERE username = $1",
        data.username
    )
    .fetch_optional(&state.db_pool)
    .await;

    match user_result {
        Ok(Some(user)) => {
            if user.password == data.password {
                let cookie = Cookie::build((SESSION_COOKIE_NAME, user.username.clone()))
                    .path("/")
                    .http_only(true)
                    .max_age(time::Duration::days(7))
                    .build(); 

                cookies = cookies.add(cookie);

                (cookies, Redirect::to("/list")).into_response()
            } else {
                Redirect::to("/login?error=Invalid%20Credentials").into_response()
            }
        }
        _ => {
            Redirect::to("/login?error=Invalid%20Credentials").into_response()
        }
    }
}

// Handler for List Page: GET /list
async fn list_handler(cookies: CookieJar) -> Response {
    if cookies.get(SESSION_COOKIE_NAME).is_some() {
        match fs::read_to_string("static/profile/list.html").await {
            Ok(content) => Html(content).into_response(),
            Err(_) => (StatusCode::NOT_FOUND, "list.html not found").into_response(),
        }
    } else {
        Redirect::to("/login?next=/list").into_response()
    }
}

// Handler for Profile Page: GET /profile
async fn profile_handler(State(state): State<AppState>, cookies: CookieJar) -> Response {
    // 1. Check for logged-in user from cookie
    let username = match cookies
        .get(SESSION_COOKIE_NAME)
        .map(|c| c.value().to_string())
    {
        Some(name) => name,
        None => return Redirect::to("/login?next=/profile").into_response(),
    };

    // 2. Fetch user data from DB
    let user_result = sqlx::query_as!(
        UserRow,
        // FIX: Updated SELECT to fetch all 6 address columns directly
        "SELECT id, first_name, last_name, username, date_of_birth, gender, phone_number, 
         address_line1, address_line2, landmark, pincode, city, state, id_proof, password 
         FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&state.db_pool)
    .await;

    let user = match user_result {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/login?error=User%20Data%20Missing").into_response(),
    };

    // 3. Read HTML template
    let template = match fs::read_to_string("static/profile/profile.html").await {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, "profile.html not found!").into_response(),
    };

    // 4. Format fields and fill template
    let dob = user
        .date_of_birth
        .map(|d| d.to_string())
        .unwrap_or_default();

    let first_name_initial = user.first_name.chars().next().map(|c| c.to_string()).unwrap_or_default();
    
    // --- FIX: Address Mapping is now direct from 6 separate columns ---
    let address_line1 = user.address_line1.unwrap_or_default();
    let address_line2 = user.address_line2.unwrap_or_default();
    let landmark = user.landmark.unwrap_or_default();
    let pincode = user.pincode.unwrap_or_default();
    let city = user.city.unwrap_or_default();
    let state = user.state.unwrap_or_default();
    // --- END FIX ---


    // NOTE: Replace the placeholders with the correctly mapped values
    let filled = template
        .replace("{{first_name_initial}}", &first_name_initial)
        .replace("{{first_name}}", &user.first_name)
        .replace("{{last_name}}", &user.last_name)
        .replace("{{username}}", &user.username)
        .replace("{{date_of_birth}}", &dob)
        .replace("{{gender}}", &user.gender.unwrap_or_default())
        .replace("{{phone_number}}", &user.phone_number.unwrap_or_default())
        .replace("{{id_proof}}", &user.id_proof.unwrap_or_default())
        // Address Fix: Separate fields are mapped directly
        .replace("{{address_line1}}", &address_line1)
        .replace("{{address_line2}}", &address_line2)
        .replace("{{landmark}}", &landmark)
        .replace("{{pincode}}", &pincode)
        .replace("{{city}}", &city)
        .replace("{{state}}", &state);

    Html(filled).into_response()
}

// Handler to clear the cookie and redirect to login
async fn logout_handler(cookies: CookieJar) -> (CookieJar, Redirect) {
    let expired_cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .max_age(time::Duration::seconds(0))
        .build(); 

    let cookies = cookies.remove(expired_cookie);
    (cookies, Redirect::to("/login"))
}

// --- 5. Main Function and Router Setup ---

#[tokio::main]
async fn main() {
    dotenv().expect("Failed to read .env file");

    // Database Pool Setup
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = PgPool::connect(&database_url)
        .await
        .expect(DB_CONNECT_ERROR);

    let app_state = AppState { db_pool: pool };

    // Static file serving setup
    let static_files_service =
        ServeDir::new("static").not_found_service(axum::routing::get(not_found_handler));

    // Application Router
    let app = Router::new()
        .route("/", get(root_handler))
        .nest_service("/static", static_files_service)
        .route(
            "/login",
            get(|| async { Redirect::to("/static/profile/login.html") }),
        )
        .route("/login", post(login_handler))
        .route(
            "/signup",
            get(|| async { Redirect::to("/static/profile/signup.html") }),
        )
        .route("/submit", post(signup_handler))
        .route("/list", get(list_handler))
        .route("/profile", get(profile_handler))
        .route("/logout", get(logout_handler))
        .fallback(not_found_handler)
        .with_state(app_state);

    // Server binding and startup
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("-> Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn not_found_handler(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("404 Not Found: {}", uri))
}