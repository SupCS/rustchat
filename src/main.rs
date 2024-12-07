mod db;
mod handlers;
mod routes;

use dotenvy::dotenv;
use std::error::Error;
use warp::Filter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    // Підключення до бази даних
    let db = db::connect_to_db().await?;

    // Реєстрація маршрутів
    let register = routes::register_routes(db.clone());
    let login = routes::login_routes(db.clone());

    // Об'єднання маршрутів
    let routes = register.or(login);

    // Запуск сервера
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}
