// Import required dependencies and modules
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const path = require("path")
const multer = require("multer")

// Configure multer for file upload handling
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads/")
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9)
    cb(null, "bukti-" + uniqueSuffix + path.extname(file.originalname))
  },
})

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true)
    } else {
      cb(new Error("Hanya file gambar yang diperbolehkan"))
    }
  },
})

// Initialize Express app and middleware
const app = express()

app.use(cors())
app.use(express.json())
app.use(express.static("public"))

// Connect to MongoDB database
mongoose.connect(
  "mongodb+srv://admin:admin123@cluster0.j9z0b5n.mongodb.net/yayasan_donasi?retryWrites=true&w=majority",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
)

// Define database schemas and models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "user"], default: "user" },
})

const donationSchema = new mongoose.Schema(
  {
    nama: { type: String, required: true },
    email: { type: String, default: "" },
    telepon: { type: String, default: "" },
    jumlah: { type: Number, required: true },
    tanggal: { type: Date, required: true },
    metodePembayaran: { type: String, required: true },
    keterangan: { type: String, default: "" },
    kategori: { type: String, default: "umum" },
    buktiPembayaran: { type: String, default: "" }, // path ke file bukti
  },
  { timestamps: true },
)

const budgetSchema = new mongoose.Schema({
  nama: { type: String, required: true },
  kategori: { type: String, required: true },
  anggaran: { type: Number, required: true },
  terpakai: { type: Number, default: 0 },
  periode: { type: String, required: true },
  status: { type: String, enum: ["active", "completed", "exceeded"], default: "active" },
  deskripsi: { type: String, default: "" },
})

const expenseSchema = new mongoose.Schema(
  {
    nama: { type: String, required: true },
    jumlah: { type: Number, required: true },
    tanggal: { type: Date, required: true },
    kategori: { type: String, required: true },
    deskripsi: { type: String, default: "" },
    budgetId: { type: mongoose.Schema.Types.ObjectId, ref: "Budget" },
  },
  { timestamps: true },
)

const User = mongoose.model("User", userSchema)
const Donation = mongoose.model("Donation", donationSchema)
const Budget = mongoose.model("Budget", budgetSchema)
const Expense = mongoose.model("Expense", expenseSchema)

// Authentication middleware - verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) return res.sendStatus(401)

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

// Authentication route - user login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body
    const user = await User.findOne({ username })

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Username atau password salah" })
    }

    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, "your-secret-key", {
      expiresIn: "24h",
    })

    res.json({ token, user: { username: user.username, role: user.role } })
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Dashboard API - get aggregated statistics and charts data
app.get("/api/dashboard", authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query
    let dateFilter = {}

    if (startDate && endDate) {
      dateFilter = { tanggal: { $gte: new Date(startDate), $lte: new Date(endDate) } }
    }

    const totalDonasi = await Donation.aggregate([
      { $match: dateFilter },
      { $group: { _id: null, total: { $sum: "$jumlah" } } },
    ])

    const totalDonatur = await Donation.countDocuments(dateFilter)

    const timelineData = await Donation.aggregate([
      { $match: dateFilter },
      { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$tanggal" } }, total: { $sum: "$jumlah" } } },
      { $sort: { _id: 1 } },
    ])

    const monthlyData = await Donation.aggregate([
      { $match: dateFilter },
      { $group: { _id: { $dateToString: { format: "%Y-%m", date: "$tanggal" } }, total: { $sum: "$jumlah" } } },
      { $sort: { _id: 1 } },
    ])

    res.json({
      totalDonasi: totalDonasi[0]?.total || 0,
      totalDonatur,
      timelineData,
      monthlyData,
    })
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Donations API - CRUD operations for donation data
app.get("/api/donations", authenticateToken, async (req, res) => {
  try {
    const { search, month, year, minAmount, category, page = 1, limit = 10, startDate, endDate } = req.query
    const filter = {}

    if (search) filter.nama = { $regex: search, $options: "i" }
    if (category) filter.kategori = category
    if (minAmount) filter.jumlah = { $gte: Number.parseInt(minAmount) }

    if (startDate && endDate) {
      filter.tanggal = { $gte: new Date(startDate), $lte: new Date(endDate) }
    } else if (month || year) {
      const dateFilter = {}
      if (year) {
        dateFilter.$gte = new Date(`${year}-01-01`)
        dateFilter.$lte = new Date(`${year}-12-31`)
      }
      if (month) {
        const startDate = new Date(`${year || new Date().getFullYear()}-${month}-01`)
        const endDate = new Date(startDate.getFullYear(), startDate.getMonth() + 1, 0)
        dateFilter.$gte = startDate
        dateFilter.$lte = endDate
      }
      if (Object.keys(dateFilter).length > 0) filter.tanggal = dateFilter
    }

    const skip = (page - 1) * limit
    const donations = await Donation.find(filter).sort({ tanggal: -1 }).skip(skip).limit(Number.parseInt(limit))
    const totalRecords = await Donation.countDocuments(filter)
    const totalAmount = await Donation.aggregate([
      { $match: filter },
      { $group: { _id: null, total: { $sum: "$jumlah" } } },
    ])

    res.json({
      donations,
      currentPage: Number.parseInt(page),
      totalPages: Math.ceil(totalRecords / limit),
      totalRecords,
      totalAmount: totalAmount[0]?.total || 0,
    })
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

app.get("/api/donations/:id", authenticateToken, async (req, res) => {
  try {
    const donation = await Donation.findById(req.params.id)
    if (!donation) return res.status(404).json({ message: "Donasi tidak ditemukan" })
    res.json(donation)
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Create new donation (admin only)
app.post("/api/donations", authenticateToken, upload.single("buktiPembayaran"), async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    const donation = new Donation({
      nama: req.body.nama,
      email: req.body.email || "",
      telepon: req.body.telepon || "",
      jumlah: Number.parseInt(req.body.jumlah),
      tanggal: new Date(req.body.tanggal),
      metodePembayaran: req.body.metodePembayaran,
      keterangan: req.body.keterangan || "",
      kategori: req.body.kategori || "umum",
      buktiPembayaran: req.file ? req.file.filename : "",
    })

    await donation.save()
    res.status(201).json(donation)
  } catch (error) {
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

// Update donation (admin only)
app.put("/api/donations/:id", authenticateToken, upload.single("buktiPembayaran"), async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    const updateData = { ...req.body }
    if (req.file) {
      updateData.buktiPembayaran = req.file.filename
    }

    const donation = await Donation.findByIdAndUpdate(req.params.id, updateData, { new: true })
    if (!donation) return res.status(404).json({ message: "Donasi tidak ditemukan" })

    res.json(donation)
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Delete donation (admin only)
app.delete("/api/donations/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    await Donation.findByIdAndDelete(req.params.id)
    res.json({ message: "Donasi berhasil dihapus" })
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Budget API - CRUD operations for budget planning
app.get("/api/budgets", authenticateToken, async (req, res) => {
  try {
    console.log("Budgets API called with query:", req.query)
    const { periode } = req.query
    const filter = periode ? { periode } : {}
    const budgets = await Budget.find(filter).sort({ periode: -1 })
    console.log("Found budgets:", budgets.length)
    res.json(budgets)
  } catch (error) {
    console.error("Budgets API error:", error)
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

// Create new budget (admin only)
app.post("/api/budgets", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }
    const budget = new Budget(req.body)
    await budget.save()
    res.status(201).json(budget)
  } catch (error) {
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

app.get("/api/budgets/:id", authenticateToken, async (req, res) => {
  try {
    const budget = await Budget.findById(req.params.id)
    if (!budget) return res.status(404).json({ message: "Budget tidak ditemukan" })
    res.json(budget)
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Update budget (admin only)
app.put("/api/budgets/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    const budget = await Budget.findByIdAndUpdate(req.params.id, req.body, { new: true })
    if (!budget) return res.status(404).json({ message: "Budget tidak ditemukan" })

    res.json(budget)
  } catch (error) {
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

// Delete budget (admin only)
app.delete("/api/budgets/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    await Budget.findByIdAndDelete(req.params.id)
    res.json({ message: "Budget berhasil dihapus" })
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Expenses API - CRUD operations for expense management
app.get("/api/expenses", authenticateToken, async (req, res) => {
  try {
    console.log("Expenses API called with query:", req.query)
    const { startDate, endDate, kategori } = req.query
    const filter = {}

    if (startDate && endDate) {
      filter.tanggal = { $gte: new Date(startDate), $lte: new Date(endDate) }
      console.log("Date filter applied:", filter.tanggal)
    }
    if (kategori) filter.kategori = kategori

    // Populate budget info
    const expenses = await Expense.find(filter).populate("budgetId", "kategori periode").sort({ tanggal: -1 })
    console.log("Found expenses:", expenses.length)

    // Add budget info to expenses
    const expensesWithBudgetInfo = expenses.map((expense) => ({
      ...expense.toObject(),
      budgetInfo: expense.budgetId ? `${expense.budgetId.kategori} - ${expense.budgetId.periode}` : null,
    }))

    const summary = await Expense.aggregate([
      { $match: filter },
      { $group: { _id: null, total: { $sum: "$jumlah" }, count: { $sum: 1 }, average: { $avg: "$jumlah" } } },
    ])

    const currentMonth = new Date()
    const monthStart = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), 1)
    const monthEnd = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 0)

    const monthlySummary = await Expense.aggregate([
      { $match: { tanggal: { $gte: monthStart, $lte: monthEnd } } },
      { $group: { _id: null, monthly: { $sum: "$jumlah" } } },
    ])

    // Calculate remaining budget
    const totalBudget = await Budget.aggregate([{ $group: { _id: null, total: { $sum: "$anggaran" } } }])
    const totalUsedBudget = await Budget.aggregate([{ $group: { _id: null, total: { $sum: "$terpakai" } } }])

    const remainingBudget = (totalBudget[0]?.total || 0) - (totalUsedBudget[0]?.total || 0)

    const result = {
      expenses: expensesWithBudgetInfo,
      summary: {
        total: summary[0]?.total || 0,
        monthly: monthlySummary[0]?.monthly || 0,
        average: summary[0]?.average || 0,
        remainingBudget: remainingBudget,
      },
    }

    console.log("Expenses API response summary:", {
      expenseCount: result.expenses.length,
      total: result.summary.total,
    })

    res.json(result)
  } catch (error) {
    console.error("Expenses API error:", error)
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

// Create new expense with budget validation (admin only)
app.post("/api/expenses", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    const { budgetId, jumlah } = req.body

    // Jika ada budget yang dipilih, cek dan update budget
    if (budgetId) {
      const budget = await Budget.findById(budgetId)
      if (!budget) {
        return res.status(404).json({ message: "Budget tidak ditemukan" })
      }

      const remainingBudget = budget.anggaran - budget.terpakai
      if (jumlah > remainingBudget) {
        return res.status(400).json({
          message: `Jumlah pengeluaran (${new Intl.NumberFormat("id-ID", { style: "currency", currency: "IDR" }).format(jumlah)}) melebihi sisa budget (${new Intl.NumberFormat("id-ID", { style: "currency", currency: "IDR" }).format(remainingBudget)})`,
        })
      }

      // Update budget terpakai
      budget.terpakai += Number.parseInt(jumlah)
      await budget.save()
    }

    const expense = new Expense({
      nama: req.body.nama,
      jumlah: Number.parseInt(jumlah),
      tanggal: new Date(req.body.tanggal),
      kategori: req.body.kategori,
      deskripsi: req.body.deskripsi,
      budgetId: budgetId || null,
    })

    await expense.save()
    res.status(201).json(expense)
  } catch (error) {
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

// Delete expense and restore budget (admin only)
app.delete("/api/expenses/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    const expense = await Expense.findById(req.params.id)
    if (!expense) {
      return res.status(404).json({ message: "Pengeluaran tidak ditemukan" })
    }

    // Jika expense terkait dengan budget, kembalikan dana ke budget
    if (expense.budgetId) {
      const budget = await Budget.findById(expense.budgetId)
      if (budget) {
        budget.terpakai -= expense.jumlah
        await budget.save()
      }
    }

    await Expense.findByIdAndDelete(req.params.id)
    res.json({ message: "Pengeluaran berhasil dihapus" })
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

app.get("/api/expenses/:id", authenticateToken, async (req, res) => {
  try {
    const expense = await Expense.findById(req.params.id)
    if (!expense) return res.status(404).json({ message: "Pengeluaran tidak ditemukan" })
    res.json(expense)
  } catch (error) {
    res.status(500).json({ message: "Server error" })
  }
})

// Update expense with budget reallocation (admin only)
app.put("/api/expenses/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "Akses ditolak" })
    }

    const oldExpense = await Expense.findById(req.params.id)
    if (!oldExpense) {
      return res.status(404).json({ message: "Pengeluaran tidak ditemukan" })
    }

    // If old expense had budget, restore the amount
    if (oldExpense.budgetId) {
      const oldBudget = await Budget.findById(oldExpense.budgetId)
      if (oldBudget) {
        oldBudget.terpakai -= oldExpense.jumlah
        await oldBudget.save()
      }
    }

    const { budgetId, jumlah } = req.body

    // If new budget is selected, check and update
    if (budgetId) {
      const budget = await Budget.findById(budgetId)
      if (!budget) {
        return res.status(404).json({ message: "Budget tidak ditemukan" })
      }

      const remainingBudget = budget.anggaran - budget.terpakai
      if (jumlah > remainingBudget) {
        return res.status(400).json({
          message: `Jumlah pengeluaran (${new Intl.NumberFormat("id-ID", { style: "currency", currency: "IDR" }).format(jumlah)}) melebihi sisa budget (${new Intl.NumberFormat("id-ID", { style: "currency", currency: "IDR" }).format(remainingBudget)})`,
        })
      }

      // Update budget terpakai
      budget.terpakai += Number.parseInt(jumlah)
      await budget.save()
    }

    const updatedExpense = await Expense.findByIdAndUpdate(
      req.params.id,
      {
        nama: req.body.nama,
        jumlah: Number.parseInt(jumlah),
        tanggal: new Date(req.body.tanggal),
        kategori: req.body.kategori,
        deskripsi: req.body.deskripsi,
        budgetId: budgetId || null,
      },
      { new: true },
    )

    res.json(updatedExpense)
  } catch (error) {
    res.status(500).json({ message: "Server error: " + error.message })
  }
})

// Serve uploaded files (static file serving)
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")))

// HTML Routes - serve static HTML pages
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")))
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")))
app.get("/riwayat", (req, res) => res.sendFile(path.join(__dirname, "public", "riwayat.html")))
app.get("/input-donasi", (req, res) => res.sendFile(path.join(__dirname, "public", "input-donasi.html")))
app.get("/laporan", (req, res) => res.sendFile(path.join(__dirname, "public", "laporan.html")))
app.get("/budget", (req, res) => res.sendFile(path.join(__dirname, "public", "budget.html")))
app.get("/expenses", (req, res) => res.sendFile(path.join(__dirname, "public", "expenses.html")))

// Start server and initialize database
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`))

// Create default admin and user accounts
async function createDefaultAdmin() {
  try {
    const adminExists = await User.findOne({ username: "admin" })
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10)
      const admin = new User({ username: "admin", password: hashedPassword, role: "admin" })
      await admin.save()
      console.log("Default admin created: admin/admin123")
    }

    const userExists = await User.findOne({ username: "user" })
    if (!userExists) {
      const hashedPassword = await bcrypt.hash("user123", 10)
      const user = new User({ username: "user", password: hashedPassword, role: "user" })
      await user.save()
      console.log("Default user created: user/user123")
    }
  } catch (error) {
    console.error("Error creating default users:", error)
  }
}

// Initialize default users when database connection is established
mongoose.connection.once("open", () => {
  console.log("Connected to MongoDB")
  createDefaultAdmin()
})
