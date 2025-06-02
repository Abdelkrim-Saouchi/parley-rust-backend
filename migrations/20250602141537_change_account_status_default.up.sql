-- Add up migration script here
ALTER TABLE users
ALTER COLUMN account_status
SET DEFAULT 'unverified';
