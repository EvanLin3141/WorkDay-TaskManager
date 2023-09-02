DROP TABLE IF EXISTS users;

CREATE TABLE users
(
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    pfp TEXT NULL,
    manager_id INTEGER NULL,
    FOREIGN KEY (manager_id) REFERENCES manager(manager_id)
);


DROP TABLE IF EXISTS task_manager;

CREATE TABLE task_manager
(
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_user_id INTEGER NOT NULL,
    task_title TEXT NOT NULL,
    task_due_date TEXT NOT NULL,
    priority TEXT NOT NULL,
    status INTEGER NOT NULL,
    manager_id INTEGER NULL,
    FOREIGN KEY (task_user_id) REFERENCES users(task_user_id)
);

DROP TABLE IF EXISTS manager;

CREATE TABLE manager
(
    manager_id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_name TEXT NOT NULL,
    password TEXT NOT NULL,
    pfp TEXT,
    email TEXT NOT NULL,
    admin TEXT
);

INSERT INTO manager (manager_name, password, email, admin) 
VALUES ('derek', 'db', 'random@gmail.com', 'admin');


