import { useState, useEffect } from 'react';
import { useToast } from "@/hooks/use-toast";
import { auth, googleProvider } from '@/lib/firebase';
import { 
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  type User as FirebaseUser
} from 'firebase/auth';

type AuthUser = {
  id: string;
  username: string;
  email: string | null;
  photoURL: string | null;
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

function convertFirebaseUser(fbUser: FirebaseUser): AuthUser {
  return {
    id: fbUser.uid,
    username: fbUser.displayName || fbUser.email?.split('@')[0] || 'User',
    email: fbUser.email,
    photoURL: fbUser.photoURL,
  };
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
      (firebaseUser) => {
        setIsLoading(false);
        if (firebaseUser) {
          console.log('User signed in:', firebaseUser.email);
          setUser(convertFirebaseUser(firebaseUser));
        } else {
          console.log('User signed out');
          setUser(null);
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
  }, []);

  // Email/Password Login
  const login = async ({ email, password }: { email: string; password: string }): Promise<RequestResult> => {
    try {
      const result = await signInWithEmailAndPassword(auth, email, password);
      return { ok: true, user: convertFirebaseUser(result.user) };
    } catch (error: any) {
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  // Email/Password Registration
  const register = async ({ email, password }: { email: string; password: string }): Promise<RequestResult> => {
    try {
      const result = await createUserWithEmailAndPassword(auth, email, password);
      return { ok: true, user: convertFirebaseUser(result.user) };
    } catch (error: any) {
      const errorMessage = await handleFirebaseError(error);
      return { ok: false, message: errorMessage };
    }
  };

  // Google Sign In
  const googleSignIn = async (): Promise<RequestResult> => {
    try {
      const result = await signInWithPopup(auth, googleProvider);
      return { ok: true, user: convertFirebaseUser(result.user) };
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