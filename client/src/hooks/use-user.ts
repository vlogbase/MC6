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
  const idToken = await getIdToken(firebaseUser);
  const response = await fetch('/api/sync-firebase-user', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ idToken }),
  });

  if (!response.ok) {
    throw new Error('Failed to sync user with database');
  }

  return response.json();
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
            const dbUser = await syncUserWithDatabase(firebaseUser);
            setUser(dbUser);
          } else {
            console.log('User signed out');
            setUser(null);
          }
        } catch (error) {
          console.error('Error syncing user:', error);
          setError(error instanceof Error ? error : new Error('Failed to sync user'));
          toast({
            title: "Error",
            description: "Failed to sync user data",
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
      }
    );

    // Cleanup subscription
    return () => unsubscribe();
  }, [toast]);

  // Email/Password Login
  const login = async ({ email, password }: { email: string; password: string }): Promise<RequestResult> => {
    try {
      const result = await signInWithEmailAndPassword(auth, email, password);
      const dbUser = await syncUserWithDatabase(result.user);
      return { ok: true, user: dbUser };
    } catch (error: any) {
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  // Email/Password Registration
  const register = async ({ email, password }: { email: string; password: string }): Promise<RequestResult> => {
    try {
      const result = await createUserWithEmailAndPassword(auth, email, password);
      const dbUser = await syncUserWithDatabase(result.user);
      return { ok: true, user: dbUser };
    } catch (error: any) {
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  // Google Sign In
  const googleSignIn = async (): Promise<RequestResult> => {
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const dbUser = await syncUserWithDatabase(result.user);
      return { ok: true, user: dbUser };
    } catch (error: any) {
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  // Logout
  const logout = async (): Promise<RequestResult> => {
    try {
      await signOut(auth);
      return { ok: true };
    } catch (error: any) {
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