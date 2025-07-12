require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB');

        app.use(session({
            secret: process.env.SESSION_SECRET,
            resave: false,
            saveUninitialized: false,
            store: MongoStore.create({
                client: mongoose.connection.getClient(),
                touchAfter: 24 * 3600
            }),
            cookie: {
                maxAge: 1000 * 60 * 60, 
                httpOnly: true,
            }
        }));

        app.get('/', (req, res) => {
            res.render('home');
        });

        app.get('/register', (req, res) => {
            res.render('register', { error: null });
        });

        app.post('/register', async (req, res) => {
            const { email, password } = req.body;

const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

    if (!passwordRegex.test(password)) {
        return res.render("register", {
            error: "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character."
        });
    }


            try {
                const newItem = new Item({ email, password });
                await newItem.save();
                req.session.userId = newItem._id;
                console.log(" Registered:", email);
                res.redirect('/secrets');
            } catch (err) {
                console.error("Registration Error:", err);
                if (err.code === 11000) {
                    res.render("register", { error: "Email already registered." });
                } else {
                    res.render("register", { error: "Registration failed. Please try again." });
                }
            }
        });

        app.get('/login', (req, res) => {
            res.render('login', { error: null });
        });

        app.post('/login', async (req, res) => {
            const { email, password } = req.body;
            try {
                const item = await Item.findOne({ email: email.toLowerCase() });

                if (!item || !(await item.isValidPassword(password))) {
                    return res.render("login", { error: "Invalid email or password." });
                }
                req.session.userId = item._id;
                console.log("Login successful:", email);
                res.redirect('/secrets');
            } catch (err) {
                console.error(" Login error:", err);
                res.render("login", { error: "Login failed. Please try again." });
            }
        });

        app.get('/secrets', isAuthenticated, async (req, res) => {
            try {
                const user = await Item.findById(req.session.userId);
                if (!user) {
                    req.session.destroy(() => res.redirect('/login'));
                    return;
                }
                res.render('secrets', { userEmail: user.email, userSecrets: user.secrets });

            } catch (err) {
                console.error(" Error fetching secrets:", err);
                res.render('secrets', { userEmail: 'Guest', userSecrets: [], error: 'Could not load secrets.' });
            }
        });

        
        app.post('/secrets', isAuthenticated, async (req, res) => {
            const { secret } = req.body;
            if (!secret || !secret.trim()) {
                return res.redirect('/secrets');
            }
            try {
                await Item.findByIdAndUpdate(req.session.userId, {
                    $push: { secrets: secret.trim() }
                });
                console.log(" Secret added for user:", req.session.userId);
                res.redirect('/secrets');
            } catch (err) {
                console.error(" Error adding secret:", err);
                res.redirect('/secrets');
            }
        });

        
        app.get('/logout', (req, res) => {
            req.session.destroy(err => {
                if (err) {
                    console.error("Error destroying session:", err);
                    return res.redirect('/secrets');
                }
                res.redirect('/');
            });
        });

        app.get('/view-users', async (req, res) => {
            try {
                const users = await Item.find({}, '-password');
                res.json(users);
            } catch (err) {
                console.error(" Error fetching users for /view-users:", err);
                res.status(500).send("Error fetching users");
            }
        });

        const PORT = process.env.PORT || 5000;
        app.listen(PORT, () => console.log(` Server running on port ${PORT}`));

    })
    .catch(err => console.error(' MongoDB Connection Error (initial):', err)); 

const itemSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    secrets: [String]
});

itemSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

itemSchema.methods.isValidPassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

const Item = mongoose.model('Item', itemSchema);

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}