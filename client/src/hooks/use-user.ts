import { useState, useEffect } from 'react';
import { useToast } from "@/hooks/use-toast";
import { auth, googleProvider } from '@/lib/firebase';
import { 
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  type User as FirebaseUser,
  getIdToken
} from 'firebase/auth';

type AuthUser = {
  id: string;
  username: string;
  email: string | null;
  ssid: string;
  apiKey: string | null;
};

type RequestResult = {
  ok: true;
  user?: AuthUser;
} | {
  ok: false;
  message: string;
};

async function handleFirebaseError(error: any): Promise<string> {
  console.error('Firebase auth error:', error);

  switch (error.code) {
    case 'auth/email-already-in-use':
      return 'An account with this email already exists';
    case 'auth/invalid-email':
      return 'Invalid email address';
    case 'auth/operation-not-allowed':
      return 'Operation not allowed - Please ensure Google Sign-in is enabled in Firebase Console';
    case 'auth/weak-password':
      return 'Password is too weak';
    case 'auth/user-disabled':
      return 'This account has been disabled';
    case 'auth/user-not-found':
    case 'auth/wrong-password':
      return 'Invalid email or password';
    case 'auth/popup-closed-by-user':
      return 'Sign in was cancelled';
    case 'auth/unauthorized-domain':
      return `This domain ${window.location.hostname} is not authorized for Google sign-in. Please add it to Firebase Console's Authorized Domains.`;
    case 'auth/internal-error':
      return 'An internal authentication error occurred. Please try again.';
    case 'auth/network-request-failed':
      return 'Network error occurred. Please check your connection and try again.';
    case 'auth/timeout':
      return 'The authentication request timed out. Please try again.';
    case 'auth/web-storage-unsupported':
      return 'Web storage is not supported or is disabled. Please enable cookies.';
    default:
      return error.message || 'An unexpected error occurred';
  }
}

async function syncUserWithDatabase(firebaseUser: FirebaseUser): Promise<AuthUser> {
  console.log('Starting user sync process...', {
    email: firebaseUser.email,
    uid: firebaseUser.uid
  });

  try {
    const idToken = await getIdToken(firebaseUser, true);
    console.log('Got fresh ID token for sync:', {
      tokenLength: idToken.length,
      tokenStart: idToken.substring(0, 10) + '...'
    });

    const response = await fetch('/api/sync-firebase-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ idToken }),
    });

    console.log('Sync response status:', response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Sync failed:', {
        status: response.status,
        error: errorText,
        headers: Object.fromEntries(response.headers.entries())
      });
      throw new Error(`Failed to sync user: ${errorText}`);
    }

    const userData = await response.json();
    console.log('User data received from sync:', {
      id: userData.id,
      username: userData.username,
      hasSSID: !!userData.ssid,
      hasAPIKey: !!userData.apiKey
    });

    if (!userData.ssid || !userData.id) {
      console.error('Invalid user data received:', userData);
      throw new Error('Received invalid user data from server');
    }

    return userData;
  } catch (error: any) {
    console.error('Sync error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    throw error;
  }
}

export function useUser() {
  const { toast } = useToast();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    console.log('Setting up Firebase auth state listener...');
    const unsubscribe = onAuthStateChanged(
      auth,
      async (firebaseUser) => {
        try {
          setIsLoading(true);
          if (firebaseUser) {
            console.log('Firebase auth state changed - User signed in:', {
              email: firebaseUser.email,
              uid: firebaseUser.uid
            });

            try {
              const dbUser = await syncUserWithDatabase(firebaseUser);
              console.log('Successfully synced user with database:', {
                id: dbUser.id,
                username: dbUser.username
              });
              setUser(dbUser);
              toast({
                title: "Success",
                description: "Successfully signed in",
              });
            } catch (syncError: any) {
              console.error('Error during user sync:', {
                message: syncError.message,
                stack: syncError.stack
              });
              await auth.signOut();
              setUser(null);
              toast({
                title: "Error",
                description: syncError.message || "Failed to sync user data. Please try again.",
                variant: "destructive",
              });
            }
          } else {
            console.log('Firebase auth state changed - User signed out');
            setUser(null);
          }
        } catch (error: any) {
          console.error('Auth state change error:', {
            message: error.message,
            stack: error.stack
          });
          setError(error instanceof Error ? error : new Error('Failed to sync user'));
          toast({
            title: "Error",
            description: error.message || "Authentication error occurred",
            variant: "destructive",
          });
        } finally {
          setIsLoading(false);
        }
      }
    );

    return () => unsubscribe();
  }, [toast]);

  const googleSignIn = async (): Promise<RequestResult> => {
    try {
      console.log('Starting Google sign-in process...');

      const result = await signInWithPopup(auth, googleProvider);
      console.log('Google sign-in popup completed:', {
        email: result.user.email,
        uid: result.user.uid
      });

      const dbUser = await syncUserWithDatabase(result.user);
      console.log('Google sign-in completed and user synced:', {
        id: dbUser.id,
        username: dbUser.username
      });

      return { ok: true, user: dbUser };
    } catch (error: any) {
      console.error('Google sign-in error:', {
        code: error.code,
        message: error.message,
        stack: error.stack
      });
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  const login = async ({ email, password }: { email: string; password: string }): Promise<RequestResult> => {
    try {
      console.log('Attempting email/password login:', email);
      const result = await signInWithEmailAndPassword(auth, email, password);
      const dbUser = await syncUserWithDatabase(result.user);
      console.log('Login successful:', dbUser);
      return { ok: true, user: dbUser };
    } catch (error: any) {
      console.error('Login error:', error);
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  const register = async ({ email, password }: { email: string; password: string }): Promise<RequestResult> => {
    try {
      console.log('Attempting to register new user:', email);
      const result = await createUserWithEmailAndPassword(auth, email, password);
      const dbUser = await syncUserWithDatabase(result.user);
      console.log('Registration successful:', dbUser);
      return { ok: true, user: dbUser };
    } catch (error: any) {
      console.error('Registration error:', error);
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  const logout = async (): Promise<RequestResult> => {
    try {
      await signOut(auth);
      console.log('Logout successful');
      return { ok: true };
    } catch (error: any) {
      console.error('Logout error:', error);
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  return {
    user,
    isLoading,
    error,
    login,
    logout,
    register,
    googleSignIn
  };
}