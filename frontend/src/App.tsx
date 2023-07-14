import { Link } from 'react-router-dom';
import axios from 'axios';
import './App.css';
import style from './App.module.css';
import logo from './assets/logo-header.png';
import icon1 from './assets/landing_page_icon_1.png';
import icon2 from './assets/landing_page_icon_2.svg';
import icon3 from './assets/landing_page_icon_3.svg';
import icon4 from './assets/landing_page_icon_4.svg';
import facebook from './assets/facebook.png';
import linkedin from './assets/linkedin.png';
import github from './assets/github.png';

axios.defaults.withCredentials = true;

function App() {
  return (
    <>
      <div className={`${style.container}`}> 
        <header className={`${style.header}`}>
          <div className={`${style.logo_container}`}>
            <Link to='/' className={`${style.link}`}>
              <img className={`${style.logo}`} src={logo} alt="Logo" />
            </Link>
          </div>
          <div className={`${style.nav_links}`}>
            <Link to='/login' className={`${style.link}`}>Login</Link>
            <Link to='/register' className={`${style.link}`}>Register</Link>
          </div>
        </header>

        <main className={`${style.main}`}>
          <div className={`${style.hero_container}`}>
            <div className={`${style.hero_tag}`}>Open Source Project</div>
            <div className={`${style.hero_title}`}>MERN with Authentication Boilerplate</div>
            <div className={`${style.hero_tagline}`}>Effortless User Authentication for Your MERN Stack Projects</div>

            <div className={`${style.hero_features_container}`}>

              <div className={`${style.hero_feature}`}>
                <div className={`${style.hero_feature_icon_container}`}>
                  <img className={`${style.hero_feature_icon}`} src={icon1} alt="security icon" />
                </div>
                <span className={`${style.hero_feature_title}`}>Implemented Strong Security Measures</span>
              </div>

              <div className={`${style.hero_feature}`}>
                <div className={`${style.hero_feature_icon_container}`}>
                  <img className={`${style.hero_feature_icon}`} src={icon2} alt="authentication icon" />
                </div>
                <span className={`${style.hero_feature_title}`}>Forgot Password, SSO, & MFA Included</span>
              </div>

              <div className={`${style.hero_feature}`}>
                <div className={`${style.hero_feature_icon_container}`}>
                  <img className={`${style.hero_feature_icon}`} src={icon3} alt="customizable icon" />
                </div>
                <span className={`${style.hero_feature_title}`}>Customizable e-mail templates, cookies, & others.</span>
              </div>

              <div className={`${style.hero_feature}`}>
                <div className={`${style.hero_feature_icon_container}`}>
                  <img className={`${style.hero_feature_icon}`} src={icon4} alt="more features icon" />
                </div>
                <span className={`${style.hero_feature_title}`}>and more...</span>
              </div>

            </div>
          </div>
        </main>

        <footer className={`${style.footer_info_container}`}>
            <div className={`${style.footer_info_developer}`}>
              Developed by: Gabriel L. Salangsang
            </div>
            <div className={`${style.footer_info_developer_social}`}>
              <a href="https://web.facebook.com/profile.php?id=100084952308524">
                <img className={`${style.footer_info_deveveloper_social_icon}`} src={facebook} alt="Facebook icon" />
              </a>
              <a href="https://www.linkedin.com/in/gabriel-salangsang-75a249190/">
                <img className={`${style.footer_info_deveveloper_social_icon}`} src={linkedin} alt="Linkedin icon" />
              </a>
              <a href="https://github.com/GabrielSalangsang013">
                <img className={`${style.footer_info_deveveloper_social_icon}`} src={github} alt="Github icon" />
              </a>
            </div>
        </footer>

      </div>
    </>
  )
}

export default App
