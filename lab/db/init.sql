-- Schema and seed data for the lab-api's SQL injection target.
-- Runs automatically on first container start via
-- /docker-entrypoint-initdb.d (see docker-compose.yml).

CREATE TABLE items (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,
    price NUMERIC(10, 2) NOT NULL
);

INSERT INTO items (name, price) VALUES
    ('Widget', 9.99),
    ('Gadget', 19.99),
    ('Gizmo', 29.99),
    ('Doohickey', 4.50);
