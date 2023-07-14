import { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { isMFAMode } from '../helpers/auth'; // Import your authentication helper
import Loading from '../components/AllRoutes/Loading/Loading';

const PublicRoutes = () => {
  const [loading, setLoading] = useState(true);
  const [mfaMode, setMFAMode] = useState(false);
  const [isErrConnectionRefused, setIsErrConnectionRefused] = useState(false);
  const [user, setUser] = useState({});

  useEffect(() => {
    const checkIfMFAMode = async () => {
      try {
        const result: any = await isMFAMode(); // Assuming this function returns a promise
        setMFAMode(result.status === 'MFA-Mode' ? true : false);
        setUser(result.status === 'MFA-Mode' ? result.user : {});
        setLoading(false);
      } catch (error) {
        // Handle any error that occurred during authentication
        setIsErrConnectionRefused(true);
      }
    };

    checkIfMFAMode();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if(isErrConnectionRefused) {
    return <Navigate to="/" />
  }

  if (loading) {
    return <Loading />; // or any loading indicator/component
  }

  if (mfaMode) {
    return <Outlet context={[user]}/> ;
  }

  return <Navigate to="/" />
};

export default PublicRoutes;