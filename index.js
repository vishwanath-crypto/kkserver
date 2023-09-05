const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const { Sequelize, DataTypes } = require('sequelize');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8081;


require('dotenv').config();

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    dialect: process.env.DB_DIALECT,
    dialectOptions: {
        timezone: process.env.DB_TIMEZONE,
    },
    timezone: process.env.DB_TIMEZONE,
});



const User = sequelize.define('users', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
}, {
    timestamps: false,
    createdAt: 'customCreatedAt',
    updatedAt: 'customUpdatedAt',
});


const ContactForm = sequelize.define('contactforms', {
    firstName: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    lastName: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    phone: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    message: {
        type: DataTypes.TEXT,
        allowNull: false,
    },

}, {
    timestamps: true,
    updatedAt: false,
});
module.exports = ContactForm;


const Member = sequelize.define('Member', {
    name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
}, {
    timestamps: true,
    updatedAt: false
});


module.exports = Member;

app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const appSecret = crypto.randomBytes(64).toString('hex');


// Create a member
app.post('/createmember', async (req, res) => {
    try {
        const { name } = req.body;
        const member = await Member.create({ name });
        res.status(201).json(member);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// List all members
app.get('/memberlist', async (req, res) => {
    try {
        const members = await Member.findAll();
        res.json(members);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Delete a member by ID
app.delete('/memberdelete/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const member = await Member.findByPk(id);

        if (!member) {
            return res.status(404).json({ error: 'Member not found' });
        }

        await member.destroy();
        res.json({ message: 'Member deleted successfully' });
    } catch (error) {
        console.error('Error deleting member:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Update a member by ID
app.put('/memberupdate/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;
        const member = await Member.findByPk(id);

        if (!member) {
            return res.status(404).json({ error: 'Member not found' });
        }

        member.name = name;
        await member.save();

        res.json(member);
    } catch (error) {
        console.error('Error updating member:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




app.use(session({
    secret: appSecret,
    resave: false,
    saveUninitialized: true,
    credentials: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
    },
}));


sequelize.sync().then(() => {
    console.log('Database synced');
}).catch(err => {
    console.error('Error syncing database:', err);
});

const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ message: 'Unauthorized' });
    }
};

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, password: hashedPassword });

        req.session.user = user;
        res.json({ message: 'User registered successfully', username: user.username });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Registration failed' });
    }
});




app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });

        if (user) {
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
                req.session.user = user;

                res.json({ message: 'Login successful', username: user.username, email: user.email });
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Login failed' });
    }
});


app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error(err);
            res.status(500).json({ message: 'Logout failed' });
        } else {
            res.clearCookie('connect.sid');
            res.json({ message: 'Logout successful' });
        }
    });
});

app.get('/api/dashboard', requireAuth, (req, res) => {
    const { username, email } = req.session.user || {};
    res.json({ message: 'Welcome to the dashboard', username, email });
});






app.get('/api/users', async (req, res) => {
    try {
        const { search } = req.query;
        let users;

        if (search) {
            users = await User.findAll({
                where: {
                    [Op.or]: [
                        { username: { [Op.iLike]: `%${search}%` } },
                        { email: { [Op.iLike]: `%${search}%` } },
                    ],
                },
                attributes: ['id', 'username', 'email'],
            });
        } else {
            users = await User.findAll({
                attributes: ['id', 'username', 'email'],
            });
        }

        res.json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error fetching users' });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const user = await User.findByPk(userId);

        if (user) {
            await user.destroy();
            res.json({ message: 'User deleted successfully' });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error deleting user' });
    }
});



app.put('/api/users/:id', async (req, res) => {
    const userId = req.params.id;
    const { username } = req.body;

    try {
        const user = await User.findByPk(userId);

        if (user) {
            await user.update({ username });
            res.json({ message: 'User updated successfully' });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating user' });
    }
});

app.get('/contactform', async (req, res) => {
    try {
        const contactForms = await ContactForm.findAll();
        res.status(200).json(contactForms);
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 'error' });
    }
});


app.post('/contactform', async (req, res) => {
    const { firstName, lastName, email, phone, message } = req.body;

    try {
        const result = await ContactForm.create({
            firstName,
            lastName,
            email,
            phone,
            message,
        });

        res.status(200).json({ status: 'success' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 'error' });
    }
});

app.delete('/contactform/:id', async (req, res) => {
    try {
        const deletedForm = await ContactForm.destroy({
            where: {
                id: req.params.id
            }
        });
        if (!deletedForm) {
            return res.status(404).json({ message: 'Contact form not found' });
        }
        res.status(200).json({ message: 'Contact form deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while deleting the contact form' });
    }
});




const multer = require('multer');
const aws = require('aws-sdk');
const { v4: uuidv4 } = require('uuid'); // Import the uuid library

const { S3 } = require('aws-sdk');

const s3 = new S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_S3_REGION,
});


aws.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_S3_REGION,
});



const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const Image = sequelize.define('images', {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true,
    },
    imageUrl: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    type: {
        type: DataTypes.STRING, // You can use DataTypes.STRING or any other appropriate data type for the "type" field.
        allowNull: false,
    },
}, {
    timestamps: true,
    updatedAt: false
});




module.exports = Image;
const generateRandomString = (length) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
};
const sharp = require('sharp');
const { spawn } = require('child_process');


app.post('/api/upload', upload.array('images', 100), async (req, res) => {
    try {
        const uploadedImages = req.files;
        const uploadedImageUrls = [];

        for (const uploadedImage of uploadedImages) {
            const { buffer, mimetype } = uploadedImage;

            const type = req.body.type;

            let resizeOptions = {};

            if (type === 'gallery') {
                resizeOptions = {
                    width: 1280,
                    height: 720,
                    fit: 'cover',
                    position: 'center',
                };
            } else if (type === 'certificate') {
                resizeOptions = {
                    width: 1280,
                    height: 960,
                    fit: 'cover',
                    position: 'center',
                };
            }

            const resizedImageBuffer = await sharp(buffer)
                .resize(resizeOptions)
                .toBuffer();

            const randomString = generateRandomString(32);
            const fileExtension = mimetype.split('/')[1];
            const newFilename = `${randomString}.${fileExtension}`;

            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: newFilename,
                Body: resizedImageBuffer,
                ContentType: mimetype,
            };

            const s3Response = await s3.upload(params).promise();
            const imageUrl = s3Response.Location;
            uploadedImageUrls.push({ imageUrl, type });
        }

        const createdImages = await Image.bulkCreate(
            uploadedImageUrls.map(({ imageUrl, type }) => ({ imageUrl, type }))
        );

        res.json({ message: 'Images uploaded successfully', imageUrls: uploadedImageUrls });
    } catch (error) {
        console.error('Error uploading images:', error);
        res.status(500).json({ message: 'Error uploading images' });
    }
});



const handleError = (res, error, message) => {
    console.error(message, error);
    res.status(500).json({ message });
};

app.get('/api/images', async (req, res) => {
    try {
        const { type } = req.query;
        const whereClause = type ? { type } : {};

        const images = await Image.findAll({ where: whereClause });
        res.json(images);
    } catch (error) {
        handleError(res, error, 'Error fetching images');
    }
});

app.delete('/api/images/:id', async (req, res) => {
    const imageId = req.params.id;
    try {
        await Image.destroy({ where: { id: imageId } });
        res.status(204).send();
    } catch (error) {
        handleError(res, error, 'Error deleting image from SQL');
    }
});

app.post('/api/delete-image', async (req, res) => {
    const { imageUrl } = req.body;
    const imageName = imageUrl.split('/').pop();

    const params = {
        Bucket: process.env.AWS_S3_BUCKET_NAME,
        Key: imageName,
    };

    try {
        await Promise.all([
            Image.destroy({ where: { imageUrl } }),
            s3.deleteObject(params).promise(),
        ]);
        res.status(204).send();
    } catch (error) {
        handleError(res, error, 'Error deleting image from SQL and AWS S3');
    }
});


const Blog = sequelize.define('Blog', {
    title: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    content: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    imageUrl: {
        type: DataTypes.STRING, // Store the image URL for the blog
        allowNull: true,
    },
}, {
    timestamps: true,
    updatedAt: false,
});

// Add a new blog
app.post('/blogupload', upload.single('image'), async (req, res) => {
    try {
        const { title, content } = req.body;

        // Handle image upload
        const file = req.file;
        let imageUrl = null;

        if (file) {
            // Generate a unique filename for the image
            const randomString = generateRandomString(32);
            const fileExtension = file.mimetype.split('/')[1];
            const newFilename = `${randomString}.${fileExtension}`;

            // Resize and compress the image using Sharp with specified options
            const resizedImageBuffer = await sharp(file.buffer)
                .resize({
                    width: 1280,
                    height: 720,
                    fit: 'cover',
                    position: 'center',
                })
                .jpeg({ quality: 70 }) // Adjust quality as needed
                .toBuffer();

            // Upload the resized image to AWS S3
            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: newFilename,
                Body: resizedImageBuffer,
                ContentType: file.mimetype,
            };

            await s3.upload(params).promise();

            // Set the image URL to the S3 object URL
            imageUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${newFilename}`;
        }

        // Create a new blog record in the database with the image URL
        const blog = await Blog.create({ title, content, imageUrl });

        res.status(201).json(blog);
    } catch (error) {
        console.error('Error creating a blog:', error);
        res.status(500).json({ error: 'Error creating a blog' });
    }
});

// Edit a blog by ID
app.put('/blog/upload/:id', upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;

        // Find the blog by ID
        const blog = await Blog.findByPk(id);

        if (!blog) {
            return res.status(404).json({ error: 'Blog not found' });
        }

        // Handle image upload (similar to the code in the POST route)
        const file = req.file;
        let imageUrl = blog.imageUrl; // Default to the existing image URL

        if (file) {
            // Generate a unique filename for the image
            const randomString = generateRandomString(32);
            const fileExtension = 'jpg'; // Set the file extension to jpg since we're using Sharp to convert to JPEG
            const newFilename = `${randomString}.${fileExtension}`;

            // Resize and compress the image using Sharp with specified options
            const resizedImageBuffer = await sharp(file.buffer)
                .resize({
                    width: 1280,
                    height: 720,
                    fit: 'cover',
                    position: 'center',
                })
                .jpeg({ quality: 70 }) // Adjust quality as needed
                .toBuffer();

            // Upload the resized image to AWS S3
            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: newFilename,
                Body: resizedImageBuffer,
                ContentType: 'image/jpeg', // Set the content type to image/jpeg
            };

            await s3.upload(params).promise();

            // Set the image URL to the S3 object URL
            imageUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${newFilename}`;
        }

        // Update the blog record in the database
        await blog.update({ title, content, imageUrl });

        res.json(blog);
    } catch (error) {
        console.error('Error editing a blog:', error);
        res.status(500).json({ error: 'Error editing a blog' });
    }
});

// Delete a blog by ID
app.delete('/blog/upload/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Find the blog by ID
        const blog = await Blog.findByPk(id);

        if (!blog) {
            return res.status(404).json({ error: 'Blog not found' });
        }

        // Delete the associated image from AWS S3 (if exists)
        if (blog.imageUrl) {
            const imageName = blog.imageUrl.split('/').pop();
            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: imageName,
            };
            await s3.deleteObject(params).promise();
        }

        // Delete the blog record from the database
        await blog.destroy();

        res.json({ message: 'Blog deleted successfully' });
    } catch (error) {
        console.error('Error deleting a blog:', error);
        res.status(500).json({ error: 'Error deleting a blog' });
    }
});

// Get all blogs
app.get('/blogs', async (req, res) => {
    try {
        const blogs = await Blog.findAll();
        res.json(blogs);
    } catch (error) {
        console.error('Error fetching blogs:', error);
        res.status(500).json({ error: 'Error fetching blogs' });
    }
});



const Event = sequelize.define('events', {
    title: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    content: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    location: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    imageUrl: {
        type: DataTypes.STRING, // Store the image URL for the event
        allowNull: true,
    },
}, {
    timestamps: true,
    updatedAt: false,
});

// Add a new event
// app.post('/eventupload'
// Import necessary packages and setup configurations

// ...

// POST route to create a new event
app.post('/eventupload', upload.single('image'), async (req, res) => {
    try {
        const { title, content, location, description } = req.body;

        // Handle image upload
        const file = req.file;
        let imageUrl = null;

        if (file) {
            const randomString = generateRandomString(32);
            const fileExtension = file.mimetype.split('/')[1];
            const newFilename = `${randomString}.${fileExtension}`;

            const resizedImageBuffer = await sharp(file.buffer)
                .resize({
                    width: 1280,
                    height: 720,
                    fit: 'cover',
                    position: 'center',
                })
                .jpeg({ quality: 70 })
                .toBuffer();

            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: newFilename,
                Body: resizedImageBuffer,
                ContentType: file.mimetype,
            };

            await s3.upload(params).promise();

            imageUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${newFilename}`;
        }

        const event = await Event.create({ title, content, location, description, imageUrl });

        res.status(201).json(event);
    } catch (error) {
        console.error('Error creating an event:', error);
        res.status(500).json({ error: 'Error creating an event' });
    }
});

// PUT route to edit an event by ID
app.put('/event/upload/:id', upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content, location, description } = req.body;

        const event = await Event.findByPk(id);

        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }

        const file = req.file;
        let imageUrl = event.imageUrl;

        if (file) {
            const randomString = generateRandomString(32);
            const fileExtension = 'jpg';
            const newFilename = `${randomString}.${fileExtension}`;

            const resizedImageBuffer = await sharp(file.buffer)
                .resize({
                    width: 1280,
                    height: 720,
                    fit: 'cover',
                    position: 'center',
                })
                .jpeg({ quality: 70 })
                .toBuffer();

            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: newFilename,
                Body: resizedImageBuffer,
                ContentType: 'image/jpeg',
            };

            await s3.upload(params).promise();

            imageUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.amazonaws.com/${newFilename}`;
        }

        await event.update({ title, content, location, description, imageUrl });

        res.json(event);
    } catch (error) {
        console.error('Error editing an event:', error);
        res.status(500).json({ error: 'Error editing an event' });
    }
});

// Other routes and configurations...

// ...
// Delete an event by ID
app.delete('/event/upload/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Find the event by ID
        const event = await Event.findByPk(id);

        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }

        // Delete the associated image from AWS S3 (if exists)
        if (event.imageUrl) {
            const imageName = event.imageUrl.split('/').pop();
            const params = {
                Bucket: process.env.AWS_S3_BUCKET_NAME,
                Key: imageName,
            };
            await s3.deleteObject(params).promise();
        }

        // Delete the event record from the database
        await event.destroy();

        res.json({ message: 'Event deleted successfully' });
    } catch (error) {
        console.error('Error deleting an event:', error);
        res.status(500).json({ error: 'Error deleting an event' });
    }
});

// Get all events
app.get('/events', async (req, res) => {
    try {
        const events = await Event.findAll();
        res.json(events);
    } catch (error) {
        console.error('Error fetching events:', error);
        res.status(500).json({ error: 'Error fetching events' });
    }
});








app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});





