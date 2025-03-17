# Security Server

A  web application for monitoring and logging user activity with role-based access control. This Flask-based security server provides a secure platform for tracking user actions, managing logs, and implementing different permission levels for administrators and standard users.

![Security Server Screenshot](https://via.placeholder.com/800x400?text=Security+Server+Dashboard)

##  Features

### Authentication System
- Secure login with session management
- Role-based access control (Admin and Standard User roles)
- Protection against unauthorized access
- Login activity logging with IP address tracking

### Activity Monitoring
- Comprehensive logging of user actions
- Timestamp recording for all activities
- IP address tracking for security analysis
- Detailed audit trails for compliance purposes

### Admin Capabilities
- View, download, and clear system logs
- Access to admin-only sections
- User management interface
- System monitoring dashboard

### User Interface
- Clean, responsive design with Tailwind CSS
- Intuitive navigation
- Role-appropriate access controls
- Visual feedback for unauthorized actions

### Security Features
- Environment variable configuration for sensitive data
- Password protection
- Session security with Flask's secret key
- Protection against unauthorized endpoint access



## User Roles and Permissions

### Admin User
- Full access to all features
- Can view, download, and clear logs
- Access to admin panel
- User management capabilities

### Standard User
- Limited access based on permissions
- Can view logs but cannot download or clear them
- Cannot access admin-only sections
- Receives visual feedback when attempting unauthorized actions


## Logging System

The application logs various activities to `activity.log`, including:
- User logins (successful and failed attempts)
- Page access
- Admin actions (log downloads, log clearing)
- Unauthorized access attempts

Log entries include timestamps, usernames, IP addresses, and action descriptions.

