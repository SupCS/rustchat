use bcrypt::{hash, verify, DEFAULT_COST};
use futures_util::stream::StreamExt;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use mongodb::bson;
use mongodb::{
    bson::{doc, Document},
    Database,
};
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reject::Reject, Reply};
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

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub sender: String,                           // Відправник
    pub receiver: String,                         // Отримувач
    pub content: String,                          // Текст повідомлення
    pub timestamp: chrono::DateTime<chrono::Utc>, // Час відправлення
}

pub async fn register_user(
    req: RegisterRequest,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = db.collection::<Document>("users");

    // Валідація логіна та пароля
    if req.username.len() < 3 {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Логін має бути не менше 3 символів"),
            StatusCode::BAD_REQUEST,
        ));
    }

    if req.password.len() < 3 {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Пароль має бути не менше 3 символів"),
            StatusCode::BAD_REQUEST,
        ));
    }

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

pub async fn login_user(
    req: LoginRequest,
    db: Database,
) -> Result<warp::reply::Response, warp::Rejection> {
    let users = db.collection::<Document>("users");

    // Валідація логіна та пароля
    if req.username.len() < 3 {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Логін має бути не менше 3 символів"),
            StatusCode::BAD_REQUEST,
        )
        .into_response());
    }

    if req.password.len() < 3 {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Пароль має бути не менше 3 символів"),
            StatusCode::BAD_REQUEST,
        )
        .into_response());
    }

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

            return Ok(warp::reply::json(&LoginResponse { token }).into_response());
        }
    }

    // Якщо користувача не знайдено або пароль невірний
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({
            "error": "Невірний логін або пароль"
        })),
        StatusCode::UNAUTHORIZED,
    )
    .into_response())
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

pub async fn send_message(
    auth_user: String,
    message: Message,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let users = db.collection::<Document>("users");

    // Перевіряємо, чи користувачі існують
    let sender_exists = users
        .find_one(doc! { "username": &message.sender }, None)
        .await
        .map_err(|_| warp::reject::custom(CustomError("Помилка бази даних".to_string())))?
        .is_some();

    let receiver_exists = users
        .find_one(doc! { "username": &message.receiver }, None)
        .await
        .map_err(|_| warp::reject::custom(CustomError("Помилка бази даних".to_string())))?
        .is_some();

    if !sender_exists || !receiver_exists {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Один із користувачів не існує"),
            StatusCode::BAD_REQUEST,
        ));
    }

    // Перевіряємо відповідність auth_user і sender
    if auth_user != message.sender {
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Ви не можете надсилати повідомлення від імені іншого користувача"),
            StatusCode::UNAUTHORIZED,
        ));
    }

    // Створюємо документ для MongoDB
    let messages = db.collection::<Document>("messages");
    let new_message = doc! {
        "sender": &message.sender,
        "receiver": &message.receiver,
        "content": &message.content,
        "timestamp": message.timestamp.to_rfc3339(),
    };

    // Додаємо повідомлення в базу даних
    if let Err(e) = messages.insert_one(new_message, None).await {
        eprintln!("Помилка збереження повідомлення: {}", e);
        return Ok(warp::reply::with_status(
            warp::reply::json(&"Не вдалося відправити повідомлення"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&"Повідомлення надіслано"),
        StatusCode::CREATED,
    ))
}

pub async fn get_messages(
    auth_user: String,
    partner: String,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let messages = db.collection::<Document>("messages");

    // Фільтр для вибірки повідомлень між auth_user і partner
    let filter = doc! {
        "$or": [
            { "sender": &auth_user, "receiver": &partner },
            { "sender": &partner, "receiver": &auth_user }
        ]
    };

    // Сортуємо повідомлення за часом у порядку зростання
    let options = mongodb::options::FindOptions::builder()
        .sort(doc! { "timestamp": 1 })
        .build();

    let mut cursor = messages.find(filter, options).await.map_err(|_| {
        warp::reject::custom(CustomError("Не вдалося отримати повідомлення".to_string()))
    })?;

    let mut message_list = vec![];
    while let Some(result) = cursor.next().await {
        if let Ok(doc) = result {
            let message: Message = bson::from_document(doc).unwrap_or_else(|_| Message {
                sender: String::new(),
                receiver: String::new(),
                content: String::new(),
                timestamp: chrono::Utc::now(),
            });
            message_list.push(message);
        }
    }

    Ok(warp::reply::json(&message_list))
}

/// Отримання залогіненого користувача
pub async fn current_user(auth_user: String) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&serde_json::json!({
        "username": auth_user
    })))
}

/// Отримання списку чатів для поточного користувача
pub async fn get_chats(
    auth_user: String,
    db: Database,
) -> Result<impl warp::Reply, warp::Rejection> {
    let messages = db.collection::<Document>("messages");

    // Фільтр для вибірки повідомлень, де поточний користувач є відправником або отримувачем
    let filter = doc! {
        "$or": [
            { "sender": &auth_user },
            { "receiver": &auth_user }
        ]
    };

    // Отримуємо всі відповідні повідомлення
    let mut cursor = messages.find(filter, None).await.map_err(|_| {
        warp::reject::custom(CustomError("Не вдалося отримати список чатів".to_string()))
    })?;

    let mut chat_partners = std::collections::HashSet::new();

    while let Some(result) = cursor.next().await {
        if let Ok(doc) = result {
            // Додаємо співрозмовників до списку (уникальні імена)
            if let Some(sender) = doc.get_str("sender").ok() {
                if sender != auth_user {
                    chat_partners.insert(sender.to_string());
                }
            }
            if let Some(receiver) = doc.get_str("receiver").ok() {
                if receiver != auth_user {
                    chat_partners.insert(receiver.to_string());
                }
            }
        }
    }

    let chat_list: Vec<String> = chat_partners.into_iter().collect();

    // Повертаємо список чатів у відповіді
    Ok(warp::reply::json(&serde_json::json!({
        "chats": chat_list
    })))
}
