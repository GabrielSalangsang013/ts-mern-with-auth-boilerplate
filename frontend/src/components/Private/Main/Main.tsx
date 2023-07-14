import { ReactNode } from 'react';
import style from './Main.module.css';

interface MainProps {
    children: ReactNode;
}

const Main = ({children}: MainProps) => {
    return (
        <main className={`${style.main}`}>
            {children}
        </main>
    )
}

export default Main;