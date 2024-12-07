use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use mongodb::{
    bson::{doc, Document},
    Database,
};
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reject::Reject};
use warp::{reject, Rejection};

#[derive(Debug)]
pub struct CustomError(pub String);

impl Reject for CustomError {}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // Ім'я користувача
    exp: usize,  // Час дії токена (в секундах)
}

/// Реєстрація нового користувача
pub async fn register_user(
    req: RegisterRequest,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = db.collection::<Document>("users");

    // Перевіряємо, чи користувач уже існує
    if let Ok(Some(_)) = users.find_one(doc! {"username": &req.username}, None).await {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Користувач уже існує"),
            StatusCode::BAD_REQUEST,
        ));
    }

    // Хешуємо пароль
    let hashed_password = hash(req.password, DEFAULT_COST).unwrap();

    // Зберігаємо нового користувача
    let new_user = doc! {
        "username": req.username,
        "password": hashed_password,
    };

    if let Err(e) = users.insert_one(new_user, None).await {
        eprintln!("Помилка збереження користувача: {}", e);
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Не вдалося зареєструвати користувача"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&"Користувач зареєстрований"),
        StatusCode::CREATED,
    ))
}

/// Вхід користувача
pub async fn login_user(
    req: LoginRequest,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = db.collection::<Document>("users");

    // Знаходимо користувача в базі
    let user = users
        .find_one(doc! {"username": &req.username}, None)
        .await
        .map_err(|_| warp::reject::custom(CustomError("Помилка бази даних".to_string())))?;

    if let Some(user) = user {
        let stored_password = user.get_str("password").map_err(|_| {
            warp::reject::custom(CustomError("Невірна структура даних".to_string()))
        })?;

        // Перевіряємо пароль
        if verify(&req.password, stored_password)
            .map_err(|_| warp::reject::custom(CustomError("Помилка хешування".to_string())))?
        {
            // Генеруємо JWT
            let expiration = chrono::Utc::now()
                .checked_add_signed(chrono::Duration::hours(24))
                .expect("Помилка генерації часу")
                .timestamp() as usize;

            let claims = Claims {
                sub: req.username,
                exp: expiration,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(
                    std::env::var("JWT_SECRET")
                        .expect("JWT_SECRET не встановлено")
                        .as_ref(),
                ),
            )
            .map_err(|_| {
                warp::reject::custom(CustomError("Помилка генерації токена".to_string()))
            })?;

            return Ok(warp::reply::json(&LoginResponse { token }));
        }
    }

    // Якщо користувача не знайдено або пароль невірний
    Ok(warp::reply::json(&serde_json::json!({
        "error": "Невірний логін або пароль"
    })))
}

/// Перевірка JWT-токена
pub async fn authorize_user(token: String) -> Result<String, Rejection> {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET не встановлено");

    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| reject::custom(CustomError("Невалідний токен".to_string())))?;

    Ok(token_data.claims.sub)
}

pub async fn protected_handler(
    username: String,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&serde_json::json!({
        "message": "Ласкаво просимо до захищеного маршруту",
        "user": username
    })))
}
