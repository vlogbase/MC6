import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
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
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Listen to auth state changes
  const { data: user, error, isLoading } = useQuery<AuthUser | null>({
    queryKey: ['auth-user'],
    queryFn: () => 
      new Promise((resolve) => {
        const unsubscribe = onAuthStateChanged(auth, (fbUser) => {
          unsubscribe();
          resolve(fbUser ? convertFirebaseUser(fbUser) : null);
        });
      }),
    staleTime: Infinity,
  });

  // Google Sign In
  const googleSignInMutation = useMutation({
    mutationFn: async () => {
      try {
        const result = await signInWithPopup(auth, googleProvider);
        return { ok: true, user: convertFirebaseUser(result.user) } as RequestResult;
      } catch (error: any) {
        const errorMessage = await handleFirebaseError(error);
        return { ok: false, message: errorMessage } as RequestResult;
      }
    }
  });

  // Email/Password Login
  const loginMutation = useMutation({
    mutationFn: async ({ email, password }: { email: string; password: string }) => {
      try {
        const result = await signInWithEmailAndPassword(auth, email, password);
        return { ok: true, user: convertFirebaseUser(result.user) } as RequestResult;
      } catch (error: any) {
        const errorMessage = await handleFirebaseError(error);
        return { ok: false, message: errorMessage } as RequestResult;
      }
    }
  });

  // Email/Password Registration
  const registerMutation = useMutation({
    mutationFn: async ({ email, password }: { email: string; password: string }) => {
      try {
        const result = await createUserWithEmailAndPassword(auth, email, password);
        return { ok: true, user: convertFirebaseUser(result.user) } as RequestResult;
      } catch (error: any) {
        const errorMessage = await handleFirebaseError(error);
        return { ok: false, message: errorMessage } as RequestResult;
      }
    }
  });

  // Logout
  const logoutMutation = useMutation({
    mutationFn: async () => {
      try {
        await signOut(auth);
        return { ok: true } as RequestResult;
      } catch (error: any) {
        const errorMessage = await handleFirebaseError(error);
        return { ok: false, message: errorMessage } as RequestResult;
      }
    },
    onSuccess: (result) => {
      if (result.ok) {
        queryClient.setQueryData(['auth-user'], null);
        toast({
          title: "Success",
          description: "Successfully logged out",
        });
      }
    }
  });

  return {
    user,
    isLoading,
    error,
    login: loginMutation.mutateAsync,
    logout: logoutMutation.mutateAsync,
    register: registerMutation.mutateAsync,
    googleSignIn: googleSignInMutation.mutateAsync
  };
}