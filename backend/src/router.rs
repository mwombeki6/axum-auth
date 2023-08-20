#[derive(Deserialize)]
pub struct LoginDetails {
    username: String,
    password: String,
}

pub fn create_router(state: AppState, folder: PathBuf) -> Router {
    let api_router = Router::new()
            .route("/register", post(register))
            .route("/login", post(login))
            .with_state(state);

    Router::new()
        .nest("/api", api_router)
        .merge(SpaRouter::new("/", static_folder).index_file("index.html"))    
}

pub async fn register(
    State(state): State<AppState>,
    Json(newuser): Json<LoginDetails>,
) -> impl IntoResponse {
    let hashed_password = bcrypt::hash(newuser.password, 10).unwrap();
    let query = sqlx::query("INSERT INTO users (username, email, password) values ($1, $2, $3")
        .bind(newuser.username)
        .bind(newuser.email)
        .bind(hashed_password)
        .execute(&state.postgres);

    match query.await {
        Ok(_) => (StatusCode::CREATED, "Account created!".to_string()).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            format!("Something went wrong: {e}"),
        )
            .into_response(),
    }
}