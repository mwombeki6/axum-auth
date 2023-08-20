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

pub async fn login(
    State(mut state): State<AppState>,
    jar: PrivateCookiesJar,
    Json(login): Json<LoginDetails>,
) -> Result<(PrivateCookiesJar, StatusCode), StatusCode> {
    let query = sqlx::query("SELECT * FROM users WHERE username = $1")
        .bind(&login.username)
        .fetch_optional(&state.postgres);

    match query.await {
        Ok(res) => {
            if bcrypt::verify(login.password, res.unwrap().get("password")).is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
            let session_id = rand::random::<u64>().to_string();

            sqlx::query("INSERT INTO sessions (session_id, user_id) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET session_id = EXCLUDED.session_id")
                .bind(&session_id)
                .bind(res.get::<i32, _>("id"))
                .execute(&state.postgres)
                .await
                .expect("Couldn't insert session :(");

            let cookie = Cookie::build("foo", session_id)
                .secure(true)
                .same_site(SameSite::Strict)
                .http_only(true)
                .path("/")
                .finish();

            Ok((jar.add(cookie), StatusCode::Ok))
        }

        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

pub async fn logout(
    State(state): State<AppState>,
    jar: PrivateCookiesJar,
) -> Result<PrivateCookiesJar, StatusCode> {
    let Some(cookie) = jar.get("foo").map(|cookie| cookie.value().to_owned()) else {
        return Ok(jar)
    };

    let query = sqlx::query("DELETE FROM sessions WHERE session_id = $1")
        .bind(cookie)
        .execute(&state.postgres);

    match query.await {
        Ok(_) => Ok(jar.remove(Cookie::named("foo"))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

