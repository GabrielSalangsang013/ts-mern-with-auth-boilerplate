import { useNavigate } from 'react-router-dom';
import { authentication } from '../../../config/firebase-config';
import { signInWithPopup, GoogleAuthProvider } from "firebase/auth";
import style from './FirebaseGoogleSignInButton.module.css';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import google from '../../../assets/google.png';

import { useSelector, useDispatch } from 'react-redux';
import { setDisable, setNotDisable, hasError, hasNoError } from '../../../actions';
import { AllReducers } from '../../../interfaces';
import { onAuthStateChanged, signOut } from 'firebase/auth';

type FirebaseGoogleSignInButtonProps = {
    text: string
}

const FirebaseGoogleSignInButton = ({text}: FirebaseGoogleSignInButtonProps) => {
    const navigate = useNavigate();
    const isDisabled = useSelector((state: AllReducers) => state.isDisabled);
    const error = useSelector((state: AllReducers) => state.error);
    const dispatch = useDispatch();

    const signInWithGoogle = () => {
        const provider = new GoogleAuthProvider();
        signInWithPopup(authentication, provider)
            .then((response: any) => {
                const sanitizedToken = DOMPurify.sanitize(response.user.accessToken);
                signOut(authentication);
                dispatch(setDisable());
                axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/sso/${text === 'signin_with' ? 'sign-in' : 'sign-up'}/firebase-google`, {
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
                .catch((error) => {
                    dispatch(setNotDisable());
                    if(error.hasOwnProperty('response')) {
                        dispatch(hasError(error.response.data.message));
                    }
                });
            })
            .catch((error) => {
                dispatch(setNotDisable());
                if(error.hasOwnProperty('response')) {
                    dispatch(hasError(error.response.data.message));
                }
            });
    }

    onAuthStateChanged(authentication, async (user)=>{
        if(user) {
            signOut(authentication);
        }
    })

    return (
        <>
            <button onClick={signInWithGoogle} className={`${style.sso_button_google}`} type="button" disabled={isDisabled ? true : false}>
                <img className={`${style.sso_button_google_icon}`} src={google} alt="" />
                {text === 'signin_with' ? 'Sign in with' : 'Sign up with'} Google
            </button>
        </>
    )
}

export default FirebaseGoogleSignInButton;