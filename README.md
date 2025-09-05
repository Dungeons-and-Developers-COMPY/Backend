# Dungeons & Developers Backend

Firstly, make sure to either be located on the UCT campus premises or use the UCT VPN the do the following tasks.

## Copy files to server
Windows:
You will need to specify the route that the files should be copied to on your respective Virtual Machine.
```Python
scp -r Backend/my_app abdibr008@dnd-vm-1.cs.uct.ac.za:
```
## Running code on the server
```Python
cd Backend
docker-compose up --build
```
On the UCT server launch in detached mode (-d) so it runs after the window is closed.
```Python
sudo docker compose up -d
```
Acess the webpage and admin panel through the following link:
```Python
https://dungeonsanddevelopers.cs.uct.ac.za
https://dungeonsanddevelopers.cs.uct.ac.za/admin
```

The following tables provide an overview of all backend routes for **Dungeons & Developers**, including Admin, Student, and Server endpoints, along with their access permissions and descriptions.

## Admin Routes

| Route | Method | Access | Description |
|-------|--------|--------|-------------|
| `/admin/run-code` | POST | Admin + Student | Executes submitted code (optionally base64 encoded) and returns the result. |
| `/admin/submit/{question number}` | POST | Admin + Student | Evaluates submitted code against stored test cases and updates statistics. |
| `/admin/manage` | POST | Admin-only | Creates a new user. Admin-only if enabled in config. |
| `/admin/questions/` | POST | Admin-only | Creates a new coding question with auto-assigned question number. |
| `/admin/add-admin` | POST | Specific Admins only | Creates a new admin user. |
| `/admin/questionsAll/` | POST | Admin-only | Returns a list of all questions with metadata. |
| `/admin/test-delete/{question id}` | POST | Admin-only | Deletes a specific question (alternate method). |
| `/admin/questions/{question id}` | POST | Admin-only | Updates a question with new data. |
| `/admin/delete-tag/{tag name}` | POST | Admin-only | Deletes a tag from all questions and related stats. |
| `/admin/questions/stats/reset` | POST | Specific Admins only | Resets all question statistics. |
| `/admin/debug-full` | GET | Admin-only | Returns all authentication, session, and request info for debugging. |
| `/admin/check-auth` | GET | Admin + Student | Returns current user’s authentication and role info. |
| `/admin/manage` | GET | Admin-only | Lists all users. |
| `/admin/questions/{question id}` | GET | Admin-only | Retrieves full data for a specific question by ID. |
| `/admin/overview` | GET | Admin-only | Returns aggregated statistics overview by tags. |
| `/admin/all-tags` | GET | Admin-only | Returns all unique tags used across questions. |
| `/admin/question/{question id}/difficulty` | GET | Admin-only | Returns the difficulty level of a specific question. |
| `/admin/question-pass-stats` | GET | Admin-only | Returns per-question statistics (attempts, passes, failures, pass rate). |
| `/admin/question/` | GET | Admin | Returns a list of all coding questions with full details. |
| `/admin/question/stats/{question number}` | GET | Admin | Retrieves attempt and pass stats for the specified question. |
| `/admin/question/random/{difficulty}` | GET | Admin | Returns a random question of the given difficulty; cycles through all questions before repeating. |
| `/admin/test-delete/{question id}` | DELETE | Admin-only | Deletes a specific question. |
| `/admin/delete-tag/{tag name}` | DELETE | Admin-only | Deletes a tag from all questions and related stats. |
| `/admin/questions/stats/reset` | DELETE | Admin-only | Resets all question statistics. |

---

## Student Routes

| Route | Method | Access | Description |
|-------|--------|--------|-------------|
| `/login` | POST | Student-only | Logs in a student using username and password. Prevents admins from using this route. |
| `/whoami` | GET | Student-only | Returns information about the currently logged-in student. Requires authentication. |

---

## Server Routes

| Route | Method | Access | Description |
|-------|--------|--------|-------------|
| `/server/register` | POST | Admin + Student | Registers a new game server with IP, port, type, and max players. |
| `/server/deregister` | POST | Admin + Student | Deregisters a game server by IP and port. |
| `/server/update-players` | POST | Admin + Student | Updates the current player count for a specific server. |
| `/server/decrement-players` | POST | Admin + Student | Decrements the player count of a specific server by 1. |
| `/server/update-time` | POST | Admin + Student | Updates a user’s time if the new time is faster. |
| `/server/reset-times` | POST | Admin-only | Resets all users’ time taken to 0.0. |
| `/server/remove-from-leaderboard` | POST | Admin-only | Removes a user from the leaderboard (sets time taken to 0.0). |
| `/server/find-available` | GET | Admin + Student | Finds an available server that isn’t full (optional type filter). |
| `/server/list` | GET | Admin + Student | Lists all active servers with their current status. |
| `/server/status/{server ip}/{server port}` | GET | Admin + Student | Retrieves status of a specific server. |
| `/server/health` | GET | Admin + Student | Returns system health and active server count. |
| `/server/leaderboard` | GET | Admin + Student | Returns all users with non-zero time taken, sorted ascending. |


