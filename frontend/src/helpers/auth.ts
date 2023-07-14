import axios from 'axios';

type isAuthenticatedPromiseType = {
  status: 'ok' | 'fail' | 'ERR_CONNECTION_REFUSED', 
  user?: object
}

type isMFAModePromiseType = {
  status: 'MFA-Mode' | 'ok' | 'fail' | 'ERR_CONNECTION_REFUSED' | any, 
  user?: object
}

export const isAuthenticated = async (): Promise<isAuthenticatedPromiseType> => {
  try {
    const response = await axios.get(`${process.env.REACT_APP_API}/api/v1/authentication/user`);
    if (response.status === 200 && response.data.status === 'ok') return {status: 'ok', user: response.data.user};
    return {status: 'fail'};
  } catch (error: any) {
    if(error.response.data.message === 'You are unauthorized user.' && error.response.data.errorCode === 300) {
      return {status: 'fail'};
    }else {
      return {status: 'ERR_CONNECTION_REFUSED'};
    }
  }
};

export const isMFAMode = async (): Promise<isMFAModePromiseType> => {
  try {
    const response = await axios.get(`${process.env.REACT_APP_API}/api/v1/authentication/user`);
    if (response.status === 200 && response.data.status === 'MFA-Mode') return {status: response.data.status, user: response.data.user};
    if (response.status === 200 && response.data.status === 'ok') return {status: response.data.status, user: response.data.user};
    return {status: 'fail'};
  } catch (error: any) {
    if(error.response.data.message === 'You are unauthorized user.' && error.response.data.errorCode === 300) {
      return {status: 'fail'};
    }else {
      return {status: 'ERR_CONNECTION_REFUSED'};
    }
  }
};