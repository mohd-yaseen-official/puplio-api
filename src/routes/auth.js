import express from 'express';
import { supabase, admin } from '../config/supabase.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

/**
 * @route   POST /signup
 * @desc    Register a new user
 * @access  Public
 */
router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      return res.status(400).json({ 
        error: error.message || 'Registration failed' 
      });
    }

    return res.status(201).json({ 
      message: 'User created successfully. Check your email for confirmation.',
    });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

/**
 * @route   POST /login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      return res.status(401).json({ 
        error: error.message || 'Login failed' 
      });
    }

    res.cookie('refreshToken', data.session.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      sameSite: 'strict'
    });

    return res.status(200).json({
      message: 'Login successful',
      access_token: data.session.access_token,
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

/**
 * @route   POST /refresh-token
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh-token', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body.refresh_token;

    if (!refreshToken) {
      return res.status(400).json({ 
        error: 'Refresh token is required' 
      });
    }

    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken
    });

    if (error) {
      res.clearCookie('refreshToken');
      return res.status(401).json({ 
        error: error.message || 'Token refreshing failed' 
      });
    }

    if (!data.session) {
      return res.status(401).json({ 
        error: 'Invalid refresh token' 
      });
    }

    res.cookie('refreshToken', data.session.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      sameSite: 'strict'
    });

    return res.status(200).json({
      access_token: data.session.access_token,
      user: {
        email: data.user.email
      }
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

/**
 * @route   POST /logout
 * @desc    Logout user
 * @access  Public
 */
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      res.clearCookie('refreshToken');    
    }

    return res.status(200).json({ 
      message: 'Logout successful' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

/**
 * @route   POST /delete
 * @desc    Delete the currently logged in user
 * @access  Private
 */
router.post('/delete', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { error: deleteError } = await admin.auth.admin.deleteUser(userId);

    if (deleteError) {
      return res.status(500).json({ 
        error: deleteError.message || 'Failed to delete user' 
      });
    }

    const refreshToken = req.cookies?.refreshToken;
    if (refreshToken) {
      res.clearCookie('refreshToken');
    }

    return res.status(200).json({ 
      message: 'User deleted successfully' 
    });
  } catch (error) {
    console.error('Delete user error:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

// /**
//  * @route   POST /forgot-password
//  * @desc    Send password reset email
//  * @access  Public
//  */
// router.post('/forgot-password', async (req, res) => {
//   try {
//     const { email } = req.body;

//     if (!email) {
//       return res.status(400).json({ 
//         error: 'Email is required' 
//       });
//     }

//     const { error } = await supabase.auth.resetPasswordForEmail(email, {
//       redirectTo: `${process.env.CLIENT_URL}/reset-password`
//     });

//     if (error) {
//       return res.status(400).json({ 
//         error: error.message || 'Password reset failed' 
//       });
//     }

//     return res.status(200).json({ 
//       message: 'Password reset email sent. Check your inbox.' 
//     });
//   } catch (error) {
//     console.error('Forgot password error:', error);
//     return res.status(500).json({ 
//       error: 'Internal server error' 
//     });
//   }
// });

// /**
//  * @route   POST /reset-password
//  * @desc    Reset user password
//  * @access  Public
//  */
// router.post('/reset-password', async (req, res) => {
//   try {
//     const { accessToken, newPassword } = req.body;

//     if (!accessToken || !newPassword) {
//       return res.status(400).json({ 
//         error: 'Access token and new password are required' 
//       });
//     }

//     const { error: sessionError } = await supabase.auth.setSession({
//       access_token: accessToken,
//       refresh_token: ''
//     });

//     if (sessionError) {
//       return res.status(400).json({ 
//         error: sessionError.message || 'Session creation failed'
//       });
//     }

//     const { error } = await supabase.auth.updateUser({
//       password: newPassword
//     });

//     if (error) {
//       return res.status(400).json({ 
//         error: error.message || 'Password update failed'
//       });
//     }

//     return res.status(200).json({ 
//       message: 'Password updated successfully' 
//     });
//   } catch (error) {
//     console.error('Reset password error:', error);
//     return res.status(500).json({ 
//       error: 'Internal server error' 
//     });
//   }
// });

export default router;