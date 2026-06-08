# Net Scanner

Net Scanner is a web app for scanning open ports on a target host and assessing their security risk.


## Features

- User scans hostname/IP for open ports.
- Scanner returns a list with open ports.
- Gives a verdict with the risk each one poses.
- Each scan gives a total risk score.
- For every open port there is an expandable info.
- Holds a history with previously scanned IP.

## Tech Stack

**Frontend:** React

**Backend:** FastAPI, nmap, pydantic, socket, asyncio


## Project Structure
backend/
  - main.py
  - models.py
  - analyzer.py
  - nmap_scanner.py

frontend/
  - app.jsx
  - app.css

## Getting Started

Before running this app
- Python 3.12
- Vite + Node.js -> React.js
- nmap (sudo apt install nmap)




    ### Installation
    Clone the repository
    ```bash
    git clone https://github.com/panven-ops/Net-Scanner.git
    cd Net-Scanner
    ```
    
    ### Run Locally

    Start the backend

    ```bash
    cd backend
    source venv/bin/activate
    
    pip install -r requirements.txt
    uvicorn main:app --reload
    ```

    Start frontend

    ```bash
    cd frontend/scanner
    npm install
    npm run dev
    ```
    Backend: http://localhost:8000
    Frontend: http://localhost:5173
    

## API Reference

#### ScanRequest

```http
  Post/scan
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `target` | `string` | `Hostname or IP to scan(e.g.scanme.nmap.org`|

#### ScanResponse



| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `target`      | `string` | `The hostname/ip that is scanned` |
| `ip`| `string`| `resolved ip` |
| `is_up` | `boolean` | `if the host is reachable` |
| `ports` | `list` | `the list of opened ports with their risk info` |
| `total_score` | `integer` | `the cumulative risk score` |
| `verdict` | `string` | `safe/suspicious/dangerous` |
| `error` | `string` | `error message, if none is empty`|

#### scan(target)

takes  a target hostname or IP and scans for potential threat - open ports.

## Risk Scoring
- Ports are categorized as low / medium / high risk
- Each open port adds to a total score (low=10, medium=25, high=40)
- Final verdict: safe (<20), suspicious (20–50), dangerous (>50)


## License

[MIT](https://choosealicense.com/licenses/mit/)

