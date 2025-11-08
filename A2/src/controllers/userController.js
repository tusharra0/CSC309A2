const { createUser: createUserService, fetchUsers: fetchUsersService } = require('../services/userService');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const toDateOnlyString = (value) => {
  if (!value) return null;
  if (typeof value === 'string') return value;
  return value.toISOString().split('T')[0];
};

exports.createUser = async (req, res) => {
  // Check role permission - only cashier, manager, and superuser can create users
  const userRole = req.user?.role;

  if (!['cashier', 'manager', 'superuser'].includes(userRole)) {
    return res.status(403).json({
      message: 'Insufficient permission to preform this action.'
    });
  }

  const body = req.body || {};

  // Check for unknown fields first
  const allowedFields = ['utorid', 'name', 'email'];
  const receivedFields = Object.keys(body);
  const unknownFields = receivedFields.filter(field => !allowedFields.includes(field));

  if (unknownFields.length > 0) {
    return res.status(400).json({
      message: `Unknown field(s): ${unknownFields.join(', ')}`
    });
  }

  const { utorid, name, email } = body;

  // Validate utorid
  if (utorid === undefined || utorid === null || utorid === '') {
    return res.status(400).json({
      message: 'Utorid is required'
    });
  }

  // Validate utorid format (alphanumeric, typically 3-8 characters)
  const utoridRegex = /^[a-z][a-z0-9]{2,7}$/;
  if (!utoridRegex.test(utorid)) {
    return res.status(400).json({
      message: 'Invalid utorid.'
    });
  }

  // Validate name
  if (name === undefined || name === null || name === '') {
    return res.status(400).json({
      message: 'Name is required'
    });
  }

  // Validate name length (max 50 characters)
  if (name.length > 50) {
    return res.status(400).json({
      message: 'Invalid name.'
    });
  }

  // Validate email
  if (email === undefined || email === null) {
    return res.status(400).json({
      message: 'Email is required'
    });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      message: 'Invalid email.'
    });
  }

  // Validate email domain
  if (!email.endsWith('@mail.utoronto.ca')) {
    return res.status(400).json({
      message: 'Invalid email domain.'
    });
  }

  try {
    const user = await createUserService({ utorid, name, email });
    return res.status(201).json(user);
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({
        message: 'A user with that utorid or email already exists'
      });
    }

    console.error('Failed to create user:', err);
    return res.status(500).json({ message: 'Failed to create user' });
  }
};

exports.getAllUsers = async (req, res) => {
  const parseBoolean = (value, field) => {
    if (value === undefined) return undefined;
    if (value === 'true') return true;
    if (value === 'false') return false;
    res.status(400).json({ error: `Invalid ${field} parameter.` });
    return null;
  };

  try {
    const page = req.query.page ? parseInt(req.query.page, 10) : 1;
    const limit = req.query.limit ? parseInt(req.query.limit, 10) : 10;

    if (!Number.isInteger(page) || page < 1) {
      return res.status(400).json({ error: 'Invalid page number' });
    }

    if (!Number.isInteger(limit) || limit < 1) {
      return res.status(400).json({ error: 'Invalid limit number' });
    }

    const verified = parseBoolean(req.query.verified, 'verified');
    if (verified === null && req.query.verified !== undefined) return;

    const activated = parseBoolean(req.query.activated, 'activated');
    if (activated === null && req.query.activated !== undefined) return;

    const result = await fetchUsersService({
      name: req.query.name,
      role: req.query.role,
      verified,
      activated,
      page,
      limit,
    });

    return res.status(200).json(result);
  } catch (err) {
    console.error('Failed to fetch users:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
};

exports.getUserById = async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);

    // Validate userId is a valid number
    if (isNaN(userId)) {
      return res.status(400).json({
        message: 'Invalid user ID'
      });
    }

    // Get the requester's role (already validated by middleware)
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        createdAt: true,
        verified: true,
        avatarUrl: true
      }
    });

    // Check if user exists
    if (!user) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    // Return the user (already filtered by the select clause above)
    return res.status(200).json({
      ...user,
      birthday: toDateOnlyString(user.birthday),
      promotions: []
    });

  } catch (err) {
    console.error('Failed to fetch user:', err);
    return res.status(500).json({ message: 'Failed to fetch user' });
  }
};

exports.updateUserById = async (req, res) => {
  try {
    const userId = parseInt(req.params.id, 10);
    const updates = req.body || {};

    // Validate userId is a valid number
    if (isNaN(userId)) {
      return res.status(400).json({
        message: 'Invalid user ID'
      });
    }

    // Get the requester's role (already validated by middleware)
    const requesterRole = req.user?.role;

    // Allowed fields for update
    const allowedFields = ['email', 'verified', 'suspicious', 'role'];
    const receivedFields = Object.keys(updates);
    const unknownFields = receivedFields.filter((field) => !allowedFields.includes(field));

    if (unknownFields.length > 0) {
      return res.status(400).json({
        message: `Unknown field(s): ${unknownFields.join(', ')}`
      });
    }

    const sanitizedUpdates = {};

    if (Object.prototype.hasOwnProperty.call(updates, 'email') && updates.email !== null) {
      if (typeof updates.email !== 'string' || updates.email.trim() === '') {
        return res.status(400).json({ message: 'Invalid email.' });
      }
      const email = updates.email.trim();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email) || !email.endsWith('@mail.utoronto.ca')) {
        return res.status(400).json({ message: 'Invalid email.' });
      }
      sanitizedUpdates.email = email;
    }

   // --- FIXED: enforce verified must be true ---
    if (Object.prototype.hasOwnProperty.call(updates, 'verified') && updates.verified !== null) {
      if (typeof updates.verified !== 'boolean' || updates.verified !== true) {
        return res.status(400).json({ message: 'Invalid verified flag.' });
      }
      sanitizedUpdates.verified = true;
    }


    if (
      Object.prototype.hasOwnProperty.call(updates, 'suspicious') &&
      updates.suspicious !== null
    ) {
      if (typeof updates.suspicious !== 'boolean') {
        return res.status(400).json({ message: 'Invalid suspicious flag.' });
      }
      sanitizedUpdates.suspicious = updates.suspicious;
    }

    if (Object.prototype.hasOwnProperty.call(updates, 'role') && updates.role !== null) {
      if (typeof updates.role !== 'string') {
        return res.status(400).json({ message: 'Invalid role.' });
      }
      const normalizedRole = updates.role.toLowerCase();
      const validRoles = ['regular', 'cashier', 'manager', 'superuser'];
      if (!validRoles.includes(normalizedRole)) {
        return res.status(400).json({ message: 'Invalid role.' });
      }
      sanitizedUpdates.role = normalizedRole;
    }

    if (Object.keys(sanitizedUpdates).length === 0) {
      return res.status(400).json({
        message: 'No update fields provided'
      });
    }

    // First, fetch the user to check if they exist and get current state
    const existingUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, utorid: true, name: true, suspicious: true, role: true }
    });

    if (!existingUser) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    // Validate role changes based on requester's role
    if (sanitizedUpdates.role !== undefined) {
      const validRolesForManager = ['regular', 'cashier'];
      const validRolesForSuperuser = ['regular', 'cashier', 'manager', 'superuser'];

      if (requesterRole === 'manager') {
        if (!validRolesForManager.includes(sanitizedUpdates.role)) {
          return res.status(403).json({
            message: 'Forbidden: Managers can only set roles to regular or cashier'
          });
        }
      } else if (requesterRole === 'superuser') {
        if (!validRolesForSuperuser.includes(sanitizedUpdates.role)) {
          return res.status(400).json({
            message: `Invalid role. Must be one of: ${validRolesForSuperuser.join(', ')}`
          });
        }
      } else {
        return res.status(403).json({ message: 'Permission denied.' });
      }
    }

    // Check if trying to promote a suspicious user to cashier
    const resultingSuspicious =
    sanitizedUpdates.suspicious !== undefined
      ? sanitizedUpdates.suspicious
      : existingUser.suspicious;
  const resultingRole = sanitizedUpdates.role ?? existingUser.role;

  // Are we PROMOTING to cashier (non-cashier -> cashier)?
  const isPromotingToCashier =
    existingUser.role !== 'cashier' && resultingRole === 'cashier';

  // Rule: cannot promote a suspicious user to cashier
  if (isPromotingToCashier && resultingSuspicious) {
    return res.status(400).json({
      message: 'Suspicious users cannot be promoted to cashier.'
    });
  }

    // Prepare update data - only include provided fields
    const updateData = {};
    if (sanitizedUpdates.email !== undefined) updateData.email = sanitizedUpdates.email;
    if (sanitizedUpdates.verified !== undefined) updateData.verified = sanitizedUpdates.verified;
    if (sanitizedUpdates.suspicious !== undefined) updateData.suspicious = sanitizedUpdates.suspicious;
    if (sanitizedUpdates.role !== undefined) updateData.role = sanitizedUpdates.role;

    // Perform the update
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        verified: true,
        suspicious: true,
        role: true
      }
    });

    // Return only the updated fields plus id, utorid, name
    const response = {
    id: updatedUser.id,
    utorid: updatedUser.utorid,
    name: updatedUser.name
  };

  // Add only the fields that were actually updated
  if (Object.prototype.hasOwnProperty.call(sanitizedUpdates, 'email')) {
    response.email = updatedUser.email;
  }
  if (Object.prototype.hasOwnProperty.call(sanitizedUpdates, 'verified')) {
    response.verified = updatedUser.verified;
  }
  if (Object.prototype.hasOwnProperty.call(sanitizedUpdates, 'suspicious')) {
    response.suspicious = updatedUser.suspicious;
  }
  if (Object.prototype.hasOwnProperty.call(sanitizedUpdates, 'role')) {
    response.role = updatedUser.role;
  }

    return res.status(200).json(response);

  } catch (err) {
    // Handle unique constraint violations (e.g., duplicate email)
    if (err.code === 'P2002') {
      return res.status(409).json({
        message: 'Email already exists'
      });
    }

    console.error('Failed to update user:', err);
    return res.status(500).json({ message: 'Failed to update user' });
  }
};

exports.getMyInfo = async (req, res) => {
  try {
    // Get the logged-in user's ID from JWT token
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({
        message: 'Unauthorized'
      });
    }

    // Fetch the user's information
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        verified: true,
        createdAt: true,
        lastLogin: true,
        avatarUrl: true
      }
    });

    if (!user) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    return res.status(200).json({
      ...user,
      birthday: toDateOnlyString(user.birthday),
      lastLogin: user.lastLogin ? user.lastLogin.toISOString() : null,
      promotions: []
    });

  } catch (err) {
    console.error('Failed to fetch user info:', err);
    return res.status(500).json({ message: 'Failed to fetch user info' });
  }
};

exports.updateMyInfo = async (req, res) => {
  try {
    // Get the logged-in user's ID from JWT token
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({
        message: 'Unauthorized'
      });
    }

    const updates = req.body || {};

    // Allowed fields for update
    const allowedFields = ['name', 'email', 'birthday', 'avatar'];
    const receivedFields = Object.keys(updates);
    const unknownFields = receivedFields.filter(field => !allowedFields.includes(field));

    if (unknownFields.length > 0) {
      return res.status(400).json({
        message: `Unknown field(s): ${unknownFields.join(', ')}`
      });
    }

    const hasAvatar = req.file !== undefined;
    const updateData = {};

    if (Object.prototype.hasOwnProperty.call(updates, 'name') && updates.name !== null) {
      if (typeof updates.name !== 'string' || updates.name.trim() === '') {
        return res.status(400).json({
          message: 'Name is required and must be a non-empty string'
        });
      }

      if (updates.name.length > 50) {
        return res.status(400).json({
          message: 'Name must be 50 characters or less'
        });
      }

      updateData.name = updates.name.trim();
    }

    if (Object.prototype.hasOwnProperty.call(updates, 'email') && updates.email !== null) {
      if (typeof updates.email !== 'string' || updates.email.trim() === '') {
        return res.status(400).json({
          message: 'Invalid email format'
        });
      }

      const emailValue = updates.email.trim();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(emailValue) || !emailValue.endsWith('@mail.utoronto.ca')) {
        return res.status(400).json({
          message: 'Invalid email format'
        });
      }

      updateData.email = emailValue;
    }

    if (Object.prototype.hasOwnProperty.call(updates, 'birthday') && updates.birthday !== null) {
    const birthday = updates.birthday;

    // Must be a string in strict YYYY-MM-DD
    if (typeof birthday !== 'string') {
      return res.status(400).json({ message: 'Invalid birthday' });
    }

    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(birthday);
    if (!match) {
      return res.status(400).json({ message: 'Invalid birthday' });
    }

    const year = Number(match[1]);
    const month = Number(match[2]); // 1-12
    const day = Number(match[3]);   // 1-31

    const date = new Date(birthday + 'T00:00:00.000Z');

    // Reject if JS auto-fixes it (e.g. 1990-02-30 -> March 2)
    if (
      Number.isNaN(date.getTime()) ||
      date.getUTCFullYear() !== year ||
      date.getUTCMonth() + 1 !== month ||
      date.getUTCDate() !== day
    ) {
      return res.status(400).json({ message: 'Invalid birthday' });
    }

    const today = new Date();
    if (date > today) {
      return res.status(400).json({ message: 'Invalid birthday' });
    }

  // Store as Date; your response already formats via toDateOnlyString(...)
  updateData.birthday = date;
}

    const hasRealUpdates = Object.keys(updateData).length > 0;
    if (!hasRealUpdates && !hasAvatar) {
      return res.status(400).json({
        message: 'No valid fields provided'
      });
    }

    // Add avatar URL if file was uploaded
    if (req.file) {
      updateData.avatarUrl = `/uploads/avatars/${req.file.filename}`;
    }

    // Perform the update
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        utorid: true,
        name: true,
        email: true,
        birthday: true,
        role: true,
        points: true,
        verified: true,
        createdAt: true,
        lastLogin: true,
        avatarUrl: true
      }
    });

    return res.status(200).json({
      ...updatedUser,
      birthday: toDateOnlyString(updatedUser.birthday),
      lastLogin: updatedUser.lastLogin ? updatedUser.lastLogin.toISOString() : null
    });

  } catch (err) {
    // Handle unique constraint violations (e.g., duplicate email)
    if (err.code === 'P2002') {
      return res.status(409).json({
        message: 'Email already exists'
      });
    }

    console.error('Failed to update user info:', err);
    return res.status(500).json({ message: 'Failed to update user info' });
  }
};

exports.updateMyPassword = async (req, res) => {
  try {
    // Get the logged-in user's ID from JWT token
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({
        message: 'Unauthorized'
      });
    }

    const { old, new: newPassword } = req.body || {};

    // Validate required fields
    if (!old || !newPassword) {
      return res.status(400).json({
        message: 'Both old and new passwords are required'
      });
    }

    // Fetch the user with password
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        password: true
      }
    });

    if (!user) {
      return res.status(404).json({
        message: 'User not found.'
      });
    }

    // Check if user has a password (some users like regular students might not)
    if (!user.password) {
      return res.status(400).json({
        message: 'No password set for this account'
      });
    }

    // Verify the old password
    const bcrypt = require('bcrypt');
    const isPasswordValid = await bcrypt.compare(old, user.password);

    if (!isPasswordValid) {
      return res.status(403).json({
        message: 'Incorrect current password'
      });
    }

    // Validate new password format
    // Requirements: 8-20 chars, at least one uppercase, one lowercase, one number, one special character
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,20}$/;

    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        message: 'Invalid new password format. Password must be 8-20 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)'
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    await prisma.user.update({
      where: { id: userId },
      data: {
        password: hashedPassword
      }
    });

    return res.status(200).json({
      message: 'Password updated successfully'
    });

  } catch (err) {
    console.error('Failed to update password:', err);
    return res.status(500).json({ message: 'Failed to update password' });
  }
};
