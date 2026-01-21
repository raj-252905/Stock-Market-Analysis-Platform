# 📈 Stock Market Analysis Platform

A powerful full-stack stock market analysis and prediction platform built with **React**, **Node.js**, **Express**, and **MongoDB**.  
Includes secure JWT authentication, role-based dashboards, dynamic user routes, live market data, and portfolio insights for smarter investing.

---

## 🚀 Features

- 🔐 User & Admin authentication with JWT
- 🧑‍💼 Role-based dashboards and redirection
- 🌐 Dynamic user routes: `/{username}/{page}`
- 📊 Live stock market data, news, alerts
- 📈 Portfolio tracking & model predictions
- 🔄 Protected routes with session persistence
- 🎨 Smooth page animations with Framer Motion
- ⚡ Backend API with Express & MongoDB integration
- ✅ Refresh-safe, auto-verified sessions
- 📌 Easily deployable as a monorepo

---

## 📂 Project Structure

```
Stock_Market_Analysis/
 ├── frontend/   # React app
 ├── backend/    # Express server & MongoDB models
 ├── .env        # Environment config
 ├── package.json
 └── README.md
```

---

## 🛠️ Setup Instructions

### 1️⃣ Clone the repo

```bash
git clone https://github.com/<your-username>/Stock_Market_Analysis.git
cd Stock_Market_Analysis
```

### 2️⃣ Install dependencies

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Backend:**
```bash
cd backend
npm install
npm run dev
```

### 3️⃣ Configure Environment

Create a `.env` file in the backend:

```env
MONGO_URI=<your-mongodb-uri>
JWT_SECRET=<your-secret-key>
PORT=5000
```

---

## 💡 Tech Stack

- **Frontend:** React, TailwindCSS, Framer Motion, Axios, React Router
- **Backend:** Node.js, Express, JWT, bcrypt, Helmet
- **Database:** MongoDB (Mongoose)

---

## ✨ Author

Built with ❤️ by [Your Name].  
Feel free to fork, improve, and make your mark!

---

## 📄 License

This project is licensed under the MIT License.

**Contributions and stars are welcome! ⭐**
