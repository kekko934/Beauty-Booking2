
import React, { createContext, useContext, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useToast } from '@/components/ui/use-toast';
import { 
  initializeAuthListener, 
  loginUser as supabaseLoginUser,
  registerUser as supabaseRegisterUser,
  logoutUser as supabaseLogoutUser,
  adminLoginUser as localAdminLoginUser,
  refreshSession
} from '@/services/authService';
import { AuthActionTypes, authReducer, initialState } from '@/reducers/authReducer';
import { useAuthEffects } from '@/hooks/useAuthEffects';
import { getSupabase } from '@/lib/supabaseClient';


const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = React.useReducer(authReducer, initialState);
  const { toast } = useToast();
  const navigate = useNavigate();
  const supabase = getSupabase();

  const { user, isAdminAuth, loading } = state;

  const onAuthStateChangeCallback = useCallback((userPayload, isAdminPayload, loadingStatus) => {
    dispatch({ 
      type: AuthActionTypes.INITIALIZE_AUTH, 
      payload: { user: userPayload, isAdmin: isAdminPayload, loading: loadingStatus }
    });
  }, [dispatch]);

  useAuthEffects(dispatch, () => initializeAuthListener(onAuthStateChangeCallback));

  useEffect(() => {
    let isMounted = true; 

    const handleVisibilityChange = async () => {
      if (document.visibilityState === 'visible' && isMounted && supabase) {
        if (state.user || state.isAdminAuth || state.loading) {
            dispatch({ type: AuthActionTypes.SET_LOADING, payload: true });
            try {
              const { data: { session: currentSession }, error: getSessionError } = await supabase.auth.getSession();
              
              if (!isMounted) return;

              if (getSessionError) {
                console.error("Error getting session on visibility change:", getSessionError);
                dispatch({ type: AuthActionTypes.INITIALIZE_AUTH, payload: { user: null, isAdmin: false, loading: false } });
                return;
              }

              if (!currentSession && (state.user && !state.isAdminAuth)) { // User was logged in, but session is now gone
                console.log("User session lost on visibility change, signing out.");
                await supabaseLogoutUser(); // Attempt to clean up Supabase state
                dispatch({ type: AuthActionTypes.LOGOUT }); // Clear local state
                toast({ title: "Sessione Scaduta", description: "Per favore, effettua nuovamente l'accesso.", variant: "destructive" });
                navigate('/login');
                return;
              }
              
              // If there is a session, or if it's an admin, refresh normally
              const { user: refreshedUser, isAdmin: refreshedIsAdmin, error: refreshError } = await refreshSession();
              if (!isMounted) return; 

              if (refreshError) {
                console.error("Error refreshing session on visibility change:", refreshError);
                if (!refreshedUser && !refreshedIsAdmin) {
                   dispatch({ type: AuthActionTypes.INITIALIZE_AUTH, payload: { user: null, isAdmin: false, loading: false } });
                } else {
                   dispatch({ type: AuthActionTypes.SET_LOADING, payload: false });
                }
              } else {
                dispatch({ 
                  type: AuthActionTypes.INITIALIZE_AUTH, 
                  payload: { user: refreshedUser, isAdmin: refreshedIsAdmin, loading: false } 
                });
              }
            } catch (e) {
              if (isMounted) {
                console.error("Exception during visibility change session refresh:", e);
                dispatch({ type: AuthActionTypes.INITIALIZE_AUTH, payload: { user: null, isAdmin: false, loading: false } });
              }
            }
        } else if (state.loading && isMounted) { 
            dispatch({ type: AuthActionTypes.SET_LOADING, payload: false });
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      isMounted = false;
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [dispatch, state.user, state.isAdminAuth, state.loading, supabase, toast, navigate]);


  const handleLogin = useCallback(async (identifier, password) => {
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: true });
    const { user: loggedInUser, error, isAdmin } = await supabaseLoginUser(identifier, password);
    
    if (error) {
      if (error.message !== "Invalid login credentials") {
        toast({ title: "Errore di Accesso", description: error.message || "Si è verificato un errore.", variant: "destructive" });
      }
      dispatch({ type: AuthActionTypes.LOGIN_FAILURE }); 
      return { user: null, error, success: false };
    }

    if (loggedInUser) {
      if (supabase) { // Refresh session to ensure claims are up-to-date
        await supabase.auth.refreshSession();
        const { data: { session: refreshedSess }} = await supabase.auth.getSession();
        const finalUser = refreshedSess?.user ? { ...loggedInUser, ...refreshedSess.user } : loggedInUser;
        dispatch({ type: AuthActionTypes.LOGIN_SUCCESS, payload: { user: finalUser, isAdmin } });
      } else {
        dispatch({ type: AuthActionTypes.LOGIN_SUCCESS, payload: { user: loggedInUser, isAdmin } });
      }
      toast({ title: "Accesso Riuscito", description: "Benvenuto!" });
      return { user: loggedInUser, error: null, success: true };
    }
    
    dispatch({ type: AuthActionTypes.LOGIN_FAILURE }); 
    return { user: null, error: { message: "Accesso fallito." }, success: false };
  }, [toast, dispatch, supabase]);

  const handleRegister = useCallback(async (fullName, username, email, password, phone) => {
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: true });
    const { user: registeredUser, error } = await supabaseRegisterUser(fullName, username, email, password, phone);
    
    if (error) {
      toast({ title: "Errore di Registrazione", description: error.message, variant: "destructive" });
      dispatch({ type: AuthActionTypes.SET_LOADING, payload: false });
      return { user: null, error };
    }
    if (registeredUser) {
      const needsConfirmation = !registeredUser.email_confirmed_at && 
                                (registeredUser.identities && registeredUser.identities.length > 0 && registeredUser.identities[0].identity_data && !registeredUser.identities[0].identity_data.email_verified);


      if (needsConfirmation) {
        toast({ title: "Registrazione Inviata", description: "Controlla la tua email per confermare l'account." });
      } else {
        toast({ title: "Registrazione Riuscita!", description: "Ora puoi effettuare il login." });
      }
    }
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: false });
    return { user: registeredUser, error: null };
  }, [toast, dispatch]);

  const handleLogout = useCallback(async () => {
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: true });
    const isAdminLoggingOut = isAdminAuth;
    await supabaseLogoutUser(); 
    
    dispatch({ type: AuthActionTypes.LOGOUT }); 
    toast({ title: isAdminLoggingOut ? "Logout Admin Riuscito" : "Logout Riuscito" });
    navigate(isAdminLoggingOut ? '/login' : '/');
  }, [toast, navigate, isAdminAuth, dispatch]);

  const handleAdminLogin = useCallback(async (usernameInput, passwordInput) => {
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: true });
    const { success, user: adminUserDetail } = localAdminLoginUser(usernameInput, passwordInput);
    
    if (success && adminUserDetail) {
      // For local admin, claims_admin is set directly in adminUserDetail
      dispatch({ type: AuthActionTypes.ADMIN_LOGIN_SUCCESS, payload: { user: adminUserDetail } }); 
      toast({ title: "Accesso Admin Riuscito", description: `Benvenuto ${adminUserDetail.user_metadata?.full_name || adminUserDetail.username}!` });
      if (supabase) await supabase.auth.refreshSession(); // Attempt to refresh if Supabase client exists
      return true;
    }
    
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: false }); 
    return false;
  }, [toast, dispatch, supabase]);

  const setUser = useCallback((userData) => {
    dispatch({ type: AuthActionTypes.SET_USER, payload: userData });
  }, [dispatch]);

  const setIsAdminAuth = useCallback((isAdmin) => {
    dispatch({ type: AuthActionTypes.SET_IS_ADMIN_AUTH, payload: isAdmin });
  }, [dispatch]);
  
  const setLoading = useCallback((isLoading) => {
    dispatch({ type: AuthActionTypes.SET_LOADING, payload: isLoading });
  }, [dispatch]);


  return (
    <AuthContext.Provider value={{ user, isAdminAuth, loading, login: handleLogin, register: handleRegister, logout: handleLogout, adminLogin: handleAdminLogin, setUser, setIsAdminAuth, setLoading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
  