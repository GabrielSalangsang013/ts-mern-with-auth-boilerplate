import ReactDOM from 'react-dom/client';
import {BrowserRouter as Router, Route, Routes, Navigate} from 'react-router-dom';

import App from './App';
import Home from './pages/Private/Home/Home';
import Login from './pages/Public/Login/Login';
import LoginVerificationCode from './pages/MFA/LoginVerificationCode/LoginVerificationCode';
import Register from './pages/Public/Register/Register';
import AccountActivation from './pages/Public/AccountActivation/AccountActivation';
import ForgotPassword from './pages/Public/ForgotPassword/ForgotPassword';
import ResetPassword from './pages/Public/ResetPassword/ResetPassword';

import MFARoutes from "./routes/MFARoutes";
import PublicRoutes from "./routes/PublicRoutes";
import PrivateRoutes from "./routes/PrivateRoutes";

import { GoogleOAuthProvider } from '@react-oauth/google';

import reducers from './reducers';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';

const store = configureStore({reducer: reducers});

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <GoogleOAuthProvider clientId={process.env.REACT_APP_SSO_GOOGLE_IDENITY_SERVICES_CLIENT_ID || ""}>
    <Provider store={store}>
      <Router>
        <Routes>
            {/* -------------- LANDING PAGE ROUTE ------------ */}
            <Route path='/' element={<App />}/>

            {/* -------------- MULTI FACTOR AUTHENTICATION ROUTES ------------ */}
            <Route element={<MFARoutes />}>
                <Route path='/login/multi-factor-authentication'element={<LoginVerificationCode />}/>
            </Route>

            {/* -------------- PUBLIC ROUTES ------------ */}
            <Route element={<PublicRoutes />}>
              <Route path='/login' element={<Login />}/>
              <Route path='/register' element={<Register />}/>
              <Route path='/activate/:token' element={<AccountActivation />}/>
              <Route path='/forgot-password' element={<ForgotPassword />}/>
              <Route path='/reset-password/:token/:csrfToken' element={<ResetPassword />}/>
            </Route>

            {/* -------------- PRIVATE ROUTES REQUIRES JWT AUTHENTICATION TOKEN ------------ */}
            <Route element={<PrivateRoutes />}>
              <Route path="/home" element={<Home />} />
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </Provider>
  </GoogleOAuthProvider>
);
