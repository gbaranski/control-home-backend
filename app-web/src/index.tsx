import React, { useState, useEffect, useContext } from 'react';
import ReactDOM from 'react-dom';
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Redirect,
  useHistory,
} from 'react-router-dom';
import routes from './routes';
import LoginPage from './pages/login';
import './services/firebase';
import LeftNavigationBar from './components/leftNavigationBar';
import { makeStyles } from '@material-ui/core';
import { UserProvider, UserContext } from './providers/userProvider';
import {
  firebaseAuth,
  convertToFirebaseUser,
  getIdToken,
} from './services/firebase';
import LoadingPage from './pages/loading';
import { ToastContainer, toast } from 'react-toastify';
import { beginWebSocketConnection } from './services/websocket';
import {
  WebsocketContext,
  WebsocketProvider,
} from './providers/websocketProvider';
import { DeviceDataProvider } from './providers/deviceDataProvider';

const useStyles = makeStyles(() => ({
  root: {
    display: 'flex',
  },
}));

const App = () => {
  const classes = useStyles();
  const history = useHistory();
  const [open, setOpen] = useState(true);
  const [authStateLoaded, setAuthStateLoaded] = useState(false);

  const { websocket, setWebsocket } = useContext(WebsocketContext);

  const { firebaseUser, setFirebaseUser } = React.useContext(UserContext);
  if (!setFirebaseUser)
    throw new Error('Expected setFirebaseUser to be true when not initalized');

  useEffect(() => {
    firebaseAuth.onAuthStateChanged(() => {
      console.log('Auth state changed');
      if (firebaseAuth.currentUser) {
        convertToFirebaseUser(firebaseAuth.currentUser).then((firebaseUser) => {
          setFirebaseUser(firebaseUser);
          setAuthStateLoaded(true);

          try {
            getIdToken()
              .then((token) => beginWebSocketConnection(token, setWebsocket))
              .catch((e) => {
                throw e;
              });
          } catch (e) {
            toast.error(e.message);
          }
          if (history.location.pathname === '/login') {
            history.replace('/welcome');
          }
        });
      } else {
        setAuthStateLoaded(true);
      }
    });
  }, [history, setFirebaseUser]);

  if (!authStateLoaded) {
    return <LoadingPage title="Retreiving user data" />;
  }
  if (!websocket || !websocket.OPEN) {
    return <LoadingPage title="Establishing WebSocket connection" />;
  }

  const SafeRoute = ({ children, ...rest }: any) => {
    if (rest.protected) {
      return (
        <Route
          {...rest}
          render={({ location }) =>
            firebaseUser ? (
              children
            ) : (
              <Redirect
                to={{
                  pathname: '/login',
                  state: { from: location },
                }}
              />
            )
          }
        />
      );
    } else {
      return <Route {...rest} render={({ location }) => children} />;
    }
  };

  const handleDrawerClose = () => {
    setOpen(false);
  };
  const handleDrawerOpen = () => {
    setOpen(true);
  };
  return (
    <div className={classes.root}>
      {firebaseUser && (
        <>
          <LeftNavigationBar
            open={open}
            handleDrawerClose={handleDrawerClose}
            handleDrawerOpen={handleDrawerOpen}
          />
        </>
      )}
      <Switch>
        {routes.map((route, index) => (
          <SafeRoute
            key={index}
            path={route.path}
            exact={route.exact}
            protected={route.protected}
            name={route.name}
            children={<route.main />}
          />
        ))}
        <Route path={'/login'} exact>
          {!firebaseUser && <LoginPage />}
        </Route>
        {/* <Route path={'/login/success'} exact>
          <LoginSuccess />
        </Route> */}
      </Switch>
    </div>
  );
};

ReactDOM.render(
  <Router>
    <UserProvider>
      <WebsocketProvider>
        <DeviceDataProvider>
          <ToastContainer />
          <App />
        </DeviceDataProvider>
      </WebsocketProvider>
    </UserProvider>
  </Router>,

  document.getElementById('root'),
);
