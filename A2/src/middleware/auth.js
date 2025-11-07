const jwt = require('jsonwebtoken');

// Verify JWT token
exports.authRequired = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'Unauthorized' });

  const token = header.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const normalizedRole =
      typeof decoded.role === 'string' ? decoded.role.toLowerCase() : decoded.role;
    req.user = {
      ...decoded,
      role: normalizedRole
    };
    next();
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
  }
};

// Check role permission
exports.requireRole = (roles) => {
  const normalizedRoles = roles.map((role) => role.toLowerCase());
  return (req, res, next) => {
    const role = typeof req.user?.role === 'string' ? req.user.role.toLowerCase() : undefined;
    if (!role || !normalizedRoles.includes(role)) {
      return res.status(403).json({ message: 'Permission denied.' });
    }
    next();
  };
};
