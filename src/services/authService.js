
import { getSupabase } from '@/lib/supabaseClient';

const adminCredentials = [
  { username: 'admin', password: 'admin', email: 'admin@example.com', fullName: 'Amministratore Master' },
  { username: 'kekko934', password: '1029229Km', email: 'kekko934.admin@example.com', fullName: 'Kekko (Admin)' },
  { username: 'valentina', password: '123456789', email: 'valentina.admin@example.com', fullName: 'Valentina (Admin)' }
];

const enrichUserWithProfile = async (supabase, user) => {
  if (!user) return null;
  try {
    const { data: profile, error: profileError } = await supabase
      .from('users')
      .select('full_name, username, phone')
      .eq('auth_user_id', user.id)
      .single();

    if (profileError && profileError.code !== 'PGRST116') {
      console.error("Error fetching user profile:", profileError);
      return user; 
    }
    return profile ? { ...user, ...profile } : user;
  } catch (e) {
    console.error("Exception fetching user profile:", e);
    return user; 
  }
};

const clearAdminLocalStorage = () => {
  localStorage.removeItem('isAdminAuth');
  localStorage.removeItem('user'); 
};

const setAdminLocalStorage = (user) => {
  localStorage.setItem('isAdminAuth', 'true');
  localStorage.setItem('user', JSON.stringify(user));
};

const isUserAdmin = (user) => {
  if (!user) return false;
  const isSupabaseAdminByEmail = adminCredentials.some(admin => admin.email === user.email);
  // Check app_metadata from Supabase user object, or the one we construct for local admin
  const hasAdminClaim = user.app_metadata?.claims_admin === true;
  return isSupabaseAdminByEmail || hasAdminClaim;
};

export const initializeAuthListener = (onAuthStateChangeCallback) => {
  const supabase = getSupabase();
  if (!supabase) {
    console.warn("Supabase client not available for auth listener.");
    onAuthStateChangeCallback(null, false, false); 
    return { unsubscribe: () => {} };
  }

  const { data: { subscription } } = supabase.auth.onAuthStateChange(
    async (_event, session) => {
      try {
        const supabaseUser = session?.user || null;
        if (supabaseUser) {
          const enrichedUser = await enrichUserWithProfile(supabase, supabaseUser);
          const isAdmin = isUserAdmin(enrichedUser);
          
          if (isAdmin) {
            setAdminLocalStorage(enrichedUser);
          } else {
            clearAdminLocalStorage(); 
          }
          onAuthStateChangeCallback(enrichedUser, isAdmin, false);
        } else {
          const localAdminUserJson = localStorage.getItem('user');
          const localIsAdminAuth = localStorage.getItem('isAdminAuth');
          let localAdminValid = false;
          let parsedLocalAdminUser = null;

          if (localIsAdminAuth === 'true' && localAdminUserJson) {
            try {
              parsedLocalAdminUser = JSON.parse(localAdminUserJson);
              if (isUserAdmin(parsedLocalAdminUser)) { 
                localAdminValid = true;
              }
            } catch (parseError) {
              console.error("Error parsing local admin user:", parseError);
            }
          }

          if (localAdminValid && parsedLocalAdminUser) {
              onAuthStateChangeCallback(parsedLocalAdminUser, true, false);
          } else {
              clearAdminLocalStorage();
              onAuthStateChangeCallback(null, false, false);
          }
        }
      } catch (error) {
        console.error("Error in onAuthStateChange handler:", error);
        clearAdminLocalStorage();
        onAuthStateChangeCallback(null, false, false);
      }
    }
  );

  (async () => {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) { 
          const localAdminUserJson = localStorage.getItem('user');
          const localIsAdminAuth = localStorage.getItem('isAdminAuth');
          if (localIsAdminAuth === 'true' && localAdminUserJson) {
              try {
                  const parsedLocalAdminUser = JSON.parse(localAdminUserJson);
                  if (isUserAdmin(parsedLocalAdminUser)) {
                      onAuthStateChangeCallback(parsedLocalAdminUser, true, false);
                      return; 
                  }
              } catch (e) { /* ignore */ }
          }
          onAuthStateChangeCallback(null, false, false);
      }
      // If there is a session, onAuthStateChange will handle it.
    } catch (error) {
      console.error("Error in initial getSession:", error);
      onAuthStateChangeCallback(null, false, false); 
    }
  })();

  return { unsubscribe: () => subscription?.unsubscribe() };
};

export const refreshSession = async () => {
  const supabase = getSupabase();
  if (!supabase) return { user: null, isAdmin: false, error: { message: "Supabase non configurato." } };

  try {
    const { data: { session }, error: sessionError } = await supabase.auth.refreshSession(); // Use refreshSession
    
    if (sessionError && sessionError.message !== "Only an authenticated user can refresh a session") { // Ignore this specific error if no one is logged in
      console.error("Error in refreshSession (refreshSession call):", sessionError);
      // Don't clear local admin if this fails, might be a network blip for a Supabase user
      // clearAdminLocalStorage(); 
      return { user: null, isAdmin: false, error: sessionError };
    }

    const currentSession = session || (await supabase.auth.getSession()).data.session;


    if (currentSession?.user) {
      const enrichedUser = await enrichUserWithProfile(supabase, currentSession.user);
      const isAdmin = isUserAdmin(enrichedUser);
      
      if (isAdmin) {
        setAdminLocalStorage(enrichedUser);
      } else {
        clearAdminLocalStorage();
      }
      return { user: enrichedUser, isAdmin, error: null };
    }
    
    const localAdminUserJson = localStorage.getItem('user');
    const localIsAdminAuth = localStorage.getItem('isAdminAuth');
    if (localIsAdminAuth === 'true' && localAdminUserJson) {
      try {
        const parsedLocalAdminUser = JSON.parse(localAdminUserJson);
        if (isUserAdmin(parsedLocalAdminUser)) {
          return { user: parsedLocalAdminUser, isAdmin: true, error: null };
        }
      } catch (e) { console.error("Error parsing local admin in refreshSession:", e); }
    }

    clearAdminLocalStorage();
    return { user: null, isAdmin: false, error: null }; 
  } catch (error) {
    console.error("Exception in refreshSession:", error);
    clearAdminLocalStorage();
    return { user: null, isAdmin: false, error: { message: "Exception refreshing session." } };
  }
};


export const loginUser = async (identifier, password) => {
  const supabase = getSupabase();
  if (!supabase) {
    return { user: null, error: { message: "Supabase non configurato." }, isAdmin: false };
  }
  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email: identifier, password });

    if (error) {
      return { user: null, error, isAdmin: false };
    }

    if (data.user) {
      // After successful Supabase login, refresh the session to ensure claims are up-to-date
      await supabase.auth.refreshSession(); 
      const { data: { session: refreshedSession } } = await supabase.auth.getSession();
      const userToEnrich = refreshedSession?.user || data.user;

      const enrichedUser = await enrichUserWithProfile(supabase, userToEnrich);
      const isAdmin = isUserAdmin(enrichedUser);

      if (isAdmin) {
        setAdminLocalStorage(enrichedUser);
      } else {
        clearAdminLocalStorage();
      }
      return { user: enrichedUser, error: null, isAdmin };
    }
    return { user: null, error: { message: "Utente non trovato o credenziali errate." }, isAdmin: false };
  } catch (error) {
    console.error("Exception in loginUser:", error);
    return { user: null, error: { message: "Exception during login." }, isAdmin: false };
  }
};

export const registerUser = async (fullName, username, email, password, phone) => {
  const supabase = getSupabase();
  if (!supabase) {
    return { user: null, error: { message: "Supabase non configurato." } };
  }
  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
          username: username,
          phone: phone,
        }
      }
    });

    if (error) {
      return { user: null, error };
    }
    clearAdminLocalStorage();
    return { user: data.user, error: null };
  } catch (error) {
    console.error("Exception in registerUser:", error);
    return { user: null, error: { message: "Exception during registration." } };
  }
};

export const logoutUser = async () => {
  const supabase = getSupabase();
  if (!supabase) {
    clearAdminLocalStorage();
    return { error: null }; 
  }
  try {
    const { error } = await supabase.auth.signOut();
    clearAdminLocalStorage(); 
    return { error };
  } catch (error) {
    console.error("Exception in logoutUser:", error);
    clearAdminLocalStorage();
    return { error: { message: "Exception during logout." } };
  }
};

export const adminLoginUser = (usernameInput, passwordInput) => {
  try {
    const adminAccount = adminCredentials.find(
      cred => cred.username.toLowerCase() === usernameInput.toLowerCase() && cred.password === passwordInput
    );

    if (adminAccount) {
      const adminUser = { 
        id: `local-admin-${adminAccount.username}`, 
        email: adminAccount.email, 
        username: adminAccount.username,
        user_metadata: { full_name: adminAccount.fullName, username: adminAccount.username },
        app_metadata: { claims_admin: true } // Explicitly set claims_admin for local admin
      };
      setAdminLocalStorage(adminUser); 
      return { success: true, user: adminUser };
    }
    return { success: false, user: null };
  } catch (error) {
    console.error("Exception in adminLoginUser:", error);
    return { success: false, user: null };
  }
};
  