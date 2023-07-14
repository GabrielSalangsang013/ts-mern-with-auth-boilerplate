import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

import { useSelector, useDispatch } from 'react-redux';
import { setDisable, setNotDisable, hasError, hasNoError } from '../../../actions';
import { AllReducers } from '../../../interfaces';

interface GoogleIdentityServicesProps {
    addButton: boolean;
    addPrompt: boolean;
    text: 'signin_with' | 'signup_with';
}

const GoogleIdentityServices = ({addButton, addPrompt, text}: GoogleIdentityServicesProps) => {
    const navigate = useNavigate();
    const isDisabled = useSelector((state: AllReducers) => state.isDisabled);
    const error = useSelector((state: AllReducers) => state.error);
    const dispatch = useDispatch();

    function googleIdentityServices(response: {credential: string}) {
        if(!isDisabled) {
            const sanitizedToken = DOMPurify.sanitize(response.credential);
            dispatch(setDisable());
            axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/sso/${text === 'signin_with' ? 'sign-in' : 'sign-up'}/google-identity-services`, {
                token: sanitizedToken
            })
            .then((response) => {
                if(response.status === 200 && response.data.status === 'ok') {
                    dispatch(setNotDisable());
                    if(error.hasError) {
                        dispatch(hasNoError());
                    }
                    navigate('/home');
                } 
            })
            .catch(function (error) {
                dispatch(setNotDisable());
                if(error.hasOwnProperty('response')) {
                    dispatch(hasError(error.response.data.message));
                }
            });
        }
    }

    useEffect(() => {
        /* global google */
        google.accounts.id.initialize({
          client_id: process.env.REACT_APP_SSO_GOOGLE_IDENITY_SERVICES_CLIENT_ID,
          callback: googleIdentityServices
        });

        if(addButton) {
            google.accounts.id.renderButton(
            document.getElementById("buttonDiv"),
            { theme: "filled_black", size: "large", width: "350px", text: text });
        }

        if(addPrompt) {
            google.accounts.id.prompt(); 
        }
      // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [])

    return (
        <>
            {addButton && <button disabled={isDisabled} type="button" id="buttonDiv"></button>}
        </>
    )
}

export default GoogleIdentityServices;