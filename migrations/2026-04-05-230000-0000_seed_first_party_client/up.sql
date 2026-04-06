INSERT INTO clients (client_id, client_type, is_first_party, name, allowed_scopes, consent_skip)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'confidential',
    true,
    'Direct Login',
    ARRAY['*'],
    true
);
