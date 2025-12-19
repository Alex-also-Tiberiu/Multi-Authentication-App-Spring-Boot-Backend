-- Migration per aggiungere il supporto CSRF token al database
-- Da eseguire prima di avviare l'applicazione con la nuova funzionalità

-- Aggiungere la colonna csrf_token alla tabella token
ALTER TABLE token ADD COLUMN csrf_token VARCHAR(255);

-- Opzionale: Aggiungere un indice per migliorare le performance
-- CREATE INDEX idx_token_csrf ON token(csrf_token);

-- Nota: I token CSRF esistenti saranno NULL fino al prossimo login degli utenti
-- Questo è normale e non causa problemi. Il token CSRF verrà generato al prossimo login.

