import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Login from './components/Login'
import Dashboard from './components/Dashboard'

function App() {
  const [sessionId, setSessionId] = useState<string | null>(
    localStorage.getItem('sessionId')
  )

  useEffect(() => {
    if (sessionId) {
      localStorage.setItem('sessionId', sessionId)
    } else {
      localStorage.removeItem('sessionId')
    }
  }, [sessionId])

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={
            sessionId ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <Login onLogin={setSessionId} />
            )
          }
        />
        <Route
          path="/dashboard"
          element={
            sessionId ? (
              <Dashboard sessionId={sessionId} onLogout={() => setSessionId(null)} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
