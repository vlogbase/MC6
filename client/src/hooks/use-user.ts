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
      return 'Operation not allowed';
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
      return 'This domain is not authorized for Google sign-in. Please contact the administrator.';
    default:
      return error.message || 'An unexpected error occurred';
  }
}

async function syncUserWithDatabase(firebaseUser: FirebaseUser): Promise<AuthUser> {
  console.log('Syncing user with database:', firebaseUser.email);

  try {
    const idToken = await getIdToken(firebaseUser, true);
    console.log('Got fresh ID token, making sync request');

    const response = await fetch('/api/sync-firebase-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ idToken }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Sync failed with status:', response.status, 'Error:', errorText);
      throw new Error(`Failed to sync user: ${errorText}`);
    }

    const userData = await response.json();
    console.log('User synced successfully with data:', userData);

    if (!userData.ssid || !userData.id) {
      console.error('Invalid user data received:', userData);
      throw new Error('Received invalid user data from server');
    }

    return userData;
  } catch (error) {
    console.error('Sync error details:', error);
    throw error;
  }
}

export function useUser() {
  const { toast } = useToast();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  // Set up the Firebase auth state listener
  useEffect(() => {
    console.log('Setting up Firebase auth state listener');
    const unsubscribe = onAuthStateChanged(
      auth,
      async (firebaseUser) => {
        try {
          setIsLoading(true);
          if (firebaseUser) {
            console.log('User signed in:', firebaseUser.email);
            try {
              const dbUser = await syncUserWithDatabase(firebaseUser);
              console.log('Setting user state:', dbUser);
              setUser(dbUser);
              toast({
                title: "Success",
                description: "Successfully signed in",
              });
            } catch (syncError) {
              console.error('Error syncing user:', syncError);
              // If sync fails, sign out the user to maintain consistent state
              await auth.signOut();
              setUser(null);
              toast({
                title: "Error",
                description: "Failed to sync user data. Please try again.",
                variant: "destructive",
              });
            }
          } else {
            console.log('User signed out');
            setUser(null);
          }
        } catch (error) {
          console.error('Auth state change error:', error);
          setError(error instanceof Error ? error : new Error('Failed to sync user'));
          toast({
            title: "Error",
            description: "Authentication error occurred",
            variant: "destructive",
          });
        } finally {
          setIsLoading(false);
        }
      },
      (error) => {
        console.error('Auth state change error:', error);
        setError(error as Error);
        setIsLoading(false);
        toast({
          title: "Error",
          description: "Authentication state monitoring failed",
          variant: "destructive",
        });
      }
    );

    return () => unsubscribe();
  }, [toast]);

  // Google Sign In
  const googleSignIn = async (): Promise<RequestResult> => {
    try {
      console.log('Initiating Google sign-in');
      const result = await signInWithPopup(auth, googleProvider);
      console.log('Google sign-in successful:', result.user.email);
      const dbUser = await syncUserWithDatabase(result.user);
      console.log('User synced after Google sign-in:', dbUser);
      return { ok: true, user: dbUser };
    } catch (error: any) {
      console.error('Google sign-in error:', error);
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  // Email/Password Login
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

  // Email/Password Registration
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

  // Logout
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