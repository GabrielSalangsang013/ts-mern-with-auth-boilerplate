import { initializeApp } from 'firebase/app';
import { getAuth } from "firebase/auth";

type firebaseConfigType = {
    readonly apiKey: string,
    readonly authDomain: string,
    readonly projectId: string,
    readonly storageBucket: string,
    readonly messagingSenderId: string,
    readonly appId: string
}

const firebaseConfig: firebaseConfigType = {
    apiKey: process.env.REACT_APP_SSO_FIREBASE_API_KEY || '',
    authDomain: process.env.REACT_APP_SSO_FIREBASE_AUTH_DOMAIN || '',
    projectId: process.env.REACT_APP_SSO_FIREBASE_PROJECT_ID || '',
    storageBucket: process.env.REACT_APP_SSO_FIREBASE_STORAGE_BUCKET || '',
    messagingSenderId: process.env.REACT_APP_SSO_FIREBASE_MESSAGING_SENDER_ID || '',
    appId: process.env.REACT_APP_SSO_FIREBASE_APP_ID || '',
};

const app = initializeApp(firebaseConfig);

export const authentication = getAuth(app);