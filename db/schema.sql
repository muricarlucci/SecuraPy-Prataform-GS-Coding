CREATE DATABASE IF NOT EXISTS seguranca;
USE seguranca;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    senha_hash VARCHAR(64) NOT NULL,
    nivel_acesso INT DEFAULT 1,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES
('admin', 'admin@securapy.com', 'd3e68b861e89c6e2c98e6c748f3777c1fa18e2246b2167015716ca89f8ebf350', 5),
('analista', 'analista@securapy.com', '0480c1364cabfc5dd558d10a69d8fec5f75e116378610dcda41c1605e773852c', 3),
('operador', 'operador@securapy.com', '19027127ab45d589136913d3a48aacc04e939f1780622e085c596ce009205a0b', 1);
