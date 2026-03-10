What app.py does :
create the app
load config
initialize extensions
register blueprints/resources

and let environment settings control debug mode.
if __name__ == '__main__':
    app.run(port=5555)

     Our Project structure / Architecture 
    backend/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── extensions.py
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── user_routes.py
│   │   ├── chama_routes.py
│   │   ├── loan_routes.py
│   │   ├── contribution_routes.py
│   │   └── vote_routes.py
│   ├── resources/
│   │   ├── User.py
│   │   ├── Chama.py
│   │   ├── Loan.py
│   │   ├── Contribution.py
│   │   └── Vote.py
│   ├── models.py
│   └── schemas.py
├── migrations/
├── run.py
├── requirements.txt
├── .env
└── .env.example

 Frontend Architecture 
 frontend/src/
├── api/
│   ├── authApi.js
│   ├── chamaApi.js
│   ├── loanApi.js
│   ├── contributionApi.js
│   └── voteApi.js
├── pages/
│   ├── LoginPage.jsx
│   ├── DashboardPage.jsx
│   ├── ChamasPage.jsx
│   ├── ContributionsPage.jsx
│   ├── LoansPage.jsx
│   └── VotesPage.jsx
├── components/
│   ├── layout/
│   ├── forms/
│   └── tables/
└── context/
    └── AuthContext.jsx


    Suggestions for our ccurrent chama improvement for better production 
    create config.py

create extensions.py
convert to create_app()
move route registration into each module
prefix routes with /api/v1/
keep only core Chama modules for MVP