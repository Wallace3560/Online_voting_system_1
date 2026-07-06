# Email Setup (Gmail)

The system sender is now set to:
- `iebconlinevotingsystem@gmail.com`

## Required environment variables (recommended)

Set these in your web server/PHP environment:

- `MAIL_FROM_ADDRESS=iebconlinevotingsystem@gmail.com`
- `MAIL_FROM_NAME=Online Voting System`
- `MAIL_SMTP_HOST=smtp.gmail.com`
- `MAIL_SMTP_PORT=587`
- `MAIL_SMTP_USERNAME=iebconlinevotingsystem@gmail.com`
- `MAIL_SMTP_PASSWORD=<gmail-app-password>`
- `MAIL_SMTP_ENCRYPTION=tls`
- `MAIL_SMTP_TIMEOUT=15`

For Gmail, use an App Password from the Google account security page.
Regular Gmail account password login is usually blocked for SMTP apps.

## Important note about Gmail "verified" sender

To appear trusted at Gmail inboxes, you must send through authenticated infrastructure.
Using only the default PHP `mail()` without proper SMTP relay/authentication may fail delivery or land in spam.

This project now attempts authenticated SMTP first, then falls back to local `mail()` only if SMTP is unavailable.

## XAMPP / php.ini quick note

If you are using XAMPP on Windows and rely on `mail()`, configure a mail relay in your PHP/mail transport.
For production-grade reliability, use authenticated SMTP transport with a proper mailer library and valid sender domain policies.

## Feature coverage

Both flows now use the system email sender configuration:
- Verification emails
- Password reset emails
