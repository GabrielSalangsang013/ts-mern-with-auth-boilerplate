import { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { isAuthenticated } from '../helpers/auth'; // Import your authentication helper
import Loading from '../components/AllRoutes/Loading/Loading';

type resultType = {
  status: 'ok' | 'fail' | 'ERR_CONNECTION_REFUSED', 
  user?: object
}

const PrivateRoutes = () => {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [isErrConnectionRefused, setIsErrConnectionRefused] = useState(false);
  const [user, setUser] = useState({});

  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        const result: resultType = await isAuthenticated();
        setAuthenticated(result.status === 'ok' ? true : false);
        setUser(result.user ? result.user : {status: 'fail'});
        setLoading(false);
      } catch (error) {
        // Handle any error that occurred during authentication
        setIsErrConnectionRefused(true);
      }
    };

    checkAuthentication();
  }, []);

  if(isErrConnectionRefused) {
    return <Navigate to="/" />
  }

  if (loading) {
    return  <Loading/>; // or any loading indicator/component
  }

  if (!authenticated) {
    return <Navigate to="/" />;
  }

  return <Outlet context={[user]}/>;
};

export default PrivateRoutes;