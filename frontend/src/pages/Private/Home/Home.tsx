import style from './Home.module.css';
import Layout from '../../../components/AllRoutes/Layout/Layout';
import Header from '../../../components/Private/Header/Header';
import Main from '../../../components/Private/Main/Main';
import Footer from '../../../components/Private/Footer/Footer';
import FlexContainer from '../../../components/Private/FlexContainer/FlexContainer';

const Home = () => {
    return (
        <Layout>   
            <Header />   
            <Main>
                <FlexContainer>
                    <div className={`${style.box_message}`}>You're logged in!</div>
                </FlexContainer>
            </Main>
            <Footer />
        </Layout>
    )
}

export default Home;