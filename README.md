# MediCare HMS (Hospital Management System)
Node.js (no dependencies) + JWT roles + JSON-file storage. Same style as the CyberShield template.

Run: `node server.js` (or run-windows.bat) -> http://localhost:3100
Test: start the server, then `node test.js` (checkpoint checks)

## Demo logins (change after first login: Staff menu, admin)
| Role | Email | Password |
|---|---|---|
| Admin | admin@hospital.local | Admin@123 |
| Doctor | doctor@hospital.local | Doctor@123 |
| Receptionist | reception@hospital.local | Reception@123 |
| Pharmacist | pharmacy@hospital.local | Pharma@123 |

## Flow
Reception: register patient -> book appointment -> Doctor: add medical record + prescription -> Pharmacist: Dispense -> Reception: create bill, mark Paid, print invoice.

## Deploy (Render)
Push this folder to GitHub -> Render > New > Blueprint. Add a Render Disk and set DATA_DIR to its path, otherwise data is erased on redeploy.
Health check: /api/health
