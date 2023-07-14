import { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { isMFAMode } from '../helpers/auth'; // Import your authentication helper
import Loading from '../components/AllRoutes/Loading/Loading';

type isMFAModeResultType = {
  status: 'MFA-Mode' | 'ok' | 'fail' | 'ERR_CONNECTION_REFUSED', 
  user?: object
}

const PublicRoutes = () => {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [isErrConnectionRefused, setIsErrConnectionRefused] = useState(false);
  const [mfa, setMFA] = useState(false);

  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        const isMFAModeResult: isMFAModeResultType = await isMFAMode(); // Assuming this function returns a promise
        setMFA(isMFAModeResult.status === 'MFA-Mode' ? true : false);
        setAuthenticated(isMFAModeResult.status === 'ok' ? true : false);
        setLoading(false);
      } catch (error) {
        // Handle any error that occurred during authentication
        setIsErrConnectionRefused(true);
      }
    };

    checkAuthentication();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if(isErrConnectionRefused === true) {
    return <Navigate to="/" />
  }

  if (loading) {
    return <Loading/>; // or any loading indicator/component
  }

  if (!authenticated && mfa) {
    return <Navigate to="/login/multi-factor-authentication" />
  }

  if(!authenticated && !mfa) {
    return <Outlet />;
  }

  return <Navigate to="/home" />
};

export default PublicRoutes;