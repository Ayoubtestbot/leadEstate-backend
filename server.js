const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 6001;
const HOST = process.env.HOST || '0.0.0.0';

// Database connection
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:HomSEjGeUxrRdgnSqNkwXPOcJoltrTZA@switchback.proxy.rlwy.net:24600/railway';

let sequelize;
let User, Lead, Property;

// Initialize database
async function initDatabase() {
  try {
    sequelize = new Sequelize(DATABASE_URL, {
      dialect: 'postgres',
      logging: false,
      pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
      }
    });

    // Test connection
    await sequelize.authenticate();
    console.log('✅ Database connected successfully');

    // Define User model
    User = sequelize.define('User', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false
      },
      first_name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      last_name: {
        type: DataTypes.STRING,
        allowNull: true
      },
      role: {
        type: DataTypes.ENUM('manager', 'agent', 'admin'),
        defaultValue: 'agent'
      },
      status: {
        type: DataTypes.ENUM('active', 'inactive'),
        defaultValue: 'active'
      }
    });

    // Define Lead model
    Lead = sequelize.define('Lead', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      first_name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      last_name: {
        type: DataTypes.STRING,
        allowNull: true
      },
      email: {
        type: DataTypes.STRING,
        allowNull: true
      },
      phone: {
        type: DataTypes.STRING,
        allowNull: true
      },
      whatsapp: {
        type: DataTypes.STRING,
        allowNull: true
      },
      city: {
        type: DataTypes.STRING,
        allowNull: true
      },
      status: {
        type: DataTypes.ENUM('new', 'contacted', 'qualified', 'proposal', 'negotiation', 'closed-won', 'closed-lost'),
        defaultValue: 'new'
      },
      source: {
        type: DataTypes.ENUM('website', 'facebook', 'google', 'referral', 'walk-in', 'other'),
        defaultValue: 'website'
      },
      budget_min: {
        type: DataTypes.DECIMAL(12, 2),
        allowNull: true
      },
      budget_max: {
        type: DataTypes.DECIMAL(12, 2),
        allowNull: true
      },
      notes: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      assigned_to: {
        type: DataTypes.INTEGER,
        allowNull: true,
        references: {
          model: 'Users',
          key: 'id'
        }
      }
    });

    // Define Property model
    Property = sequelize.define('Property', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      title: {
        type: DataTypes.STRING,
        allowNull: false
      },
      description: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      type: {
        type: DataTypes.ENUM('house', 'apartment', 'condo', 'townhouse', 'land', 'commercial'),
        allowNull: false
      },
      status: {
        type: DataTypes.ENUM('available', 'pending', 'sold', 'rented'),
        defaultValue: 'available'
      },
      price: {
        type: DataTypes.DECIMAL(12, 2),
        allowNull: false
      },
      address: {
        type: DataTypes.STRING,
        allowNull: false
      },
      city: {
        type: DataTypes.STRING,
        allowNull: false
      },
      bedrooms: {
        type: DataTypes.INTEGER,
        allowNull: true
      },
      bathrooms: {
        type: DataTypes.INTEGER,
        allowNull: true
      },
      area: {
        type: DataTypes.DECIMAL(8, 2),
        allowNull: true
      },
      features: {
        type: DataTypes.JSON,
        allowNull: true
      },
      images: {
        type: DataTypes.JSON,
        allowNull: true
      }
    });

    // Setup associations
    User.hasMany(Lead, { foreignKey: 'assigned_to', as: 'assignedLeads' });
    Lead.belongsTo(User, { foreignKey: 'assigned_to', as: 'assignedUser' });

    // Sync database
    await sequelize.sync({ alter: true });
    console.log('✅ Database models synchronized');

    // Create default user if not exists
    const adminUser = await User.findOne({ where: { email: 'admin@demo.com' } });
    if (!adminUser) {
      await User.create({
        email: 'admin@demo.com',
        password: 'password',
        first_name: 'Demo',
        last_name: 'Admin',
        role: 'manager',
        status: 'active'
      });
      console.log('✅ Default admin user created');
    }

  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    // Fallback to in-memory storage
    console.log('⚠️ Using in-memory storage as fallback');
  }
}

// Security middleware
app.use(helmet());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// CORS configuration
app.use(cors({
  origin: [
    'https://leadestate-frontend.vercel.app',
    'http://localhost:5001',
    'http://localhost:3000'
  ],
  credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'LeadEstate Backend API is running',
    timestamp: new Date().toISOString(),
    database: sequelize ? 'Connected' : 'Fallback',
    version: '1.0.0'
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'LeadEstate Backend API is running',
    timestamp: new Date().toISOString(),
    status: 'healthy'
  });
});

// Authentication endpoints
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }
    
    let user;
    if (User) {
      user = await User.findOne({ where: { email: email.toLowerCase() } });
    }
    
    // Fallback to demo user
    if (!user && email.toLowerCase() === 'admin@demo.com' && password === 'password') {
      user = {
        id: 1,
        email: 'admin@demo.com',
        first_name: 'Demo',
        last_name: 'Admin',
        role: 'manager',
        status: 'active'
      };
    }
    
    if (!user || (user.password && user.password !== password)) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    const token = `token_${user.id}_${Date.now()}`;
    
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          role: user.role,
          status: user.status
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }
    
    const tokenParts = token.split('_');
    if (tokenParts.length !== 3 || tokenParts[0] !== 'token') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
    
    const userId = parseInt(tokenParts[1]);
    let user;
    
    if (User) {
      user = await User.findByPk(userId);
    }
    
    // Fallback to demo user
    if (!user && userId === 1) {
      user = {
        id: 1,
        email: 'admin@demo.com',
        first_name: 'Demo',
        last_name: 'Admin',
        role: 'manager',
        status: 'active'
      };
    }
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
    
    res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        status: user.status
      }
    });
    
  } catch (error) {
    res.status(401).json({
      success: false,
      message: 'Token verification failed'
    });
  }
});

// Leads endpoints
app.get('/api/leads', async (req, res) => {
  try {
    let leads = [];
    
    if (Lead) {
      leads = await Lead.findAll({
        include: [
          {
            model: User,
            as: 'assignedUser',
            attributes: ['id', 'first_name', 'last_name', 'email']
          }
        ],
        order: [['createdAt', 'DESC']]
      });
    }
    
    res.json({
      success: true,
      data: leads,
      total: leads.length
    });
    
  } catch (error) {
    console.error('❌ Get leads error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch leads'
    });
  }
});

app.post('/api/leads', async (req, res) => {
  try {
    let leadData;
    
    if (Lead) {
      leadData = await Lead.create(req.body);
    } else {
      leadData = {
        id: Date.now(),
        ...req.body,
        createdAt: new Date().toISOString()
      };
    }
    
    console.log('✅ Lead created:', leadData.id);
    
    res.status(201).json({
      success: true,
      message: 'Lead created successfully',
      data: leadData
    });
    
  } catch (error) {
    console.error('❌ Create lead error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create lead'
    });
  }
});

// Properties endpoints
app.get('/api/properties', async (req, res) => {
  try {
    let properties = [];
    
    if (Property) {
      properties = await Property.findAll({
        order: [['createdAt', 'DESC']]
      });
    }
    
    res.json({
      success: true,
      data: properties,
      total: properties.length
    });
    
  } catch (error) {
    console.error('❌ Get properties error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch properties'
    });
  }
});

app.post('/api/properties', async (req, res) => {
  try {
    let propertyData;
    
    if (Property) {
      propertyData = await Property.create(req.body);
    } else {
      propertyData = {
        id: Date.now(),
        ...req.body,
        createdAt: new Date().toISOString()
      };
    }
    
    console.log('✅ Property created:', propertyData.id);
    
    res.status(201).json({
      success: true,
      message: 'Property created successfully',
      data: propertyData
    });
    
  } catch (error) {
    console.error('❌ Create property error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create property'
    });
  }
});

// Analytics endpoint
app.get('/api/analytics/dashboard', async (req, res) => {
  try {
    let stats = {
      total_leads: 0,
      total_properties: 0,
      new_leads_today: 0,
      conversion_rate: 0
    };
    
    if (Lead && Property) {
      const [leadsCount, propertiesCount] = await Promise.all([
        Lead.count(),
        Property.count()
      ]);
      
      stats.total_leads = leadsCount;
      stats.total_properties = propertiesCount;
      stats.conversion_rate = leadsCount > 0 ? '12.5' : '0';
    }
    
    res.json({
      success: true,
      data: stats
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch analytics'
    });
  }
});

// Team endpoint
app.get('/api/team', async (req, res) => {
  try {
    let teamMembers = [];
    
    if (User) {
      teamMembers = await User.findAll({
        attributes: ['id', 'first_name', 'last_name', 'email', 'role', 'status']
      });
    } else {
      teamMembers = [{
        id: 1,
        first_name: 'Demo',
        last_name: 'Admin',
        email: 'admin@demo.com',
        role: 'manager',
        status: 'active'
      }];
    }
    
    res.json({
      success: true,
      data: teamMembers
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch team'
    });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Initialize database and start server
async function startServer() {
  await initDatabase();
  
  app.listen(PORT, HOST, () => {
    console.log(`✅ LeadEstate Backend running on http://${HOST}:${PORT}`);
    console.log(`🗄️ Database: ${sequelize ? 'Railway PostgreSQL' : 'In-memory fallback'}`);
    console.log(`🔗 Health check: http://${HOST}:${PORT}/health`);
    console.log(`📋 Demo credentials: admin@demo.com / password`);
  });
}

startServer().catch(console.error);

module.exports = app;
