const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const XLSX = require('xlsx');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = 'tms_secret_key_2026';

// ── DB Setup ──────────────────────────────────────
const adapter = new FileSync(path.join(__dirname, 'db.json'));
const db = low(adapter);

// ── Middleware ─────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const upload = multer({ storage: multer.memoryStorage() });

// ── Auth Middleware ────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'جلسة منتهية' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'للمدير فقط' });
  next();
}

function canManage(req, res, next) {
  if (!['admin', 'manager', 'dataentry'].includes(req.user.role))
    return res.status(403).json({ error: 'غير مصرح' });
  next();
}

// ══════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email, active: true }).value();
  if (!user) return res.status(401).json({ error: 'البريد الإلكتروني غير موجود' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

// ══════════════════════════════════════════════════
// USERS (admin only)
// ══════════════════════════════════════════════════
app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
  const users = db.get('users').map(u => ({ ...u, password: undefined })).value();
  res.json(users);
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const { name, email, password, role } = req.body;
  if (db.get('users').find({ email }).value())
    return res.status(400).json({ error: 'البريد مستخدم مسبقاً' });
  const hash = await bcrypt.hash(password || '123456', 10);
  const user = { id: uuidv4(), name, email, password: hash, role, active: true, createdAt: new Date().toISOString().split('T')[0] };
  db.get('users').push(user).write();
  res.json({ ...user, password: undefined });
});

app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const { name, email, role, active, password } = req.body;
  const updates = { name, email, role, active };
  if (password) updates.password = await bcrypt.hash(password, 10);
  db.get('users').find({ id: req.params.id }).assign(updates).write();
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, adminOnly, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'لا يمكن حذف حسابك' });
  db.get('users').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// ══════════════════════════════════════════════════
// PROGRAMS
// ══════════════════════════════════════════════════
app.get('/api/programs', authMiddleware, (req, res) => {
  res.json(db.get('programs').value());
});

app.post('/api/programs', authMiddleware, canManage, (req, res) => {
  const program = { id: uuidv4(), ...req.body, createdAt: new Date().toISOString().split('T')[0] };
  db.get('programs').push(program).write();
  res.json(program);
});

app.put('/api/programs/:id', authMiddleware, canManage, (req, res) => {
  db.get('programs').find({ id: req.params.id }).assign(req.body).write();
  res.json({ success: true });
});

app.delete('/api/programs/:id', authMiddleware, canManage, (req, res) => {
  db.get('programs').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// ══════════════════════════════════════════════════
// SUBJECTS
// ══════════════════════════════════════════════════
app.get('/api/subjects', authMiddleware, (req, res) => {
  let subjects = db.get('subjects').value();
  if (req.query.programId) subjects = subjects.filter(s => s.programId === req.query.programId);
  if (req.query.semester) subjects = subjects.filter(s => s.semester === parseInt(req.query.semester));
  subjects.sort((a, b) => a.semester - b.semester || a.part - b.part || a.courseCode.localeCompare(b.courseCode));
  res.json(subjects);
});

app.post('/api/subjects', authMiddleware, canManage, (req, res) => {
  if (db.get('subjects').find({ courseCode: req.body.courseCode, programId: req.body.programId }).value())
    return res.status(400).json({ error: 'رمز المادة موجود مسبقاً في هذا البرنامج' });
  const subject = { id: uuidv4(), ...req.body };
  db.get('subjects').push(subject).write();
  res.json(subject);
});

app.put('/api/subjects/:id', authMiddleware, canManage, (req, res) => {
  db.get('subjects').find({ id: req.params.id }).assign(req.body).write();
  res.json({ success: true });
});

app.delete('/api/subjects/:id', authMiddleware, canManage, (req, res) => {
  db.get('subjects').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// رفع Excel للمواد
app.post('/api/subjects/upload', authMiddleware, canManage, upload.single('file'), (req, res) => {
  try {
    const wb = XLSX.read(req.file.buffer);
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
    const programId = req.body.programId;
    let added = 0, skipped = 0, errors = [];
    for (const row of rows) {
      const courseCode = String(row['course_code'] || row['رمز المادة'] || '').trim();
      if (!courseCode) { errors.push('صف بدون رمز مادة'); continue; }
      if (db.get('subjects').find({ courseCode, programId }).value()) { skipped++; continue; }
      db.get('subjects').push({
        id: uuidv4(), courseCode, programId,
        name: row['name'] || row['اسم المادة'] || courseCode,
        semester: parseInt(row['semester'] || row['الفصل'] || 1),
        part: parseInt(row['part'] || row['الجزء'] || 1),
        creditHours: parseFloat(row['credit_hours'] || row['الوحدات'] || 3),
        weeklyHours: parseFloat(row['weekly_hours'] || row['الساعات الأسبوعية'] || 3),
        lectureHours: parseFloat(row['lecture_hours'] || row['ساعات نظري'] || 2),
        practicalHours: parseFloat(row['practical_hours'] || row['ساعات عملي'] || 0),
        tutorialHours: parseFloat(row['tutorial_hours'] || row['ساعات تمارين'] || 0),
        prerequisite: row['prerequisite'] || row['المتطلب السابق'] || ''
      }).write();
      added++;
    }
    res.json({ total: rows.length, added, skipped, errors });
  } catch (e) {
    res.status(400).json({ error: 'فشل في قراءة الملف: ' + e.message });
  }
});

// ══════════════════════════════════════════════════
// TEACHERS
// ══════════════════════════════════════════════════
app.get('/api/teachers', authMiddleware, (req, res) => {
  const teachers = db.get('teachers').value()
    .sort((a, b) => a.name.localeCompare(b.name, 'ar'));
  res.json(teachers);
});

app.post('/api/teachers', authMiddleware, canManage, (req, res) => {
  if (db.get('teachers').find({ idNumber: req.body.idNumber }).value())
    return res.status(400).json({ error: 'رقم الهوية مستخدم مسبقاً' });
  const teacher = { id: uuidv4(), available: true, maxLoad: 16, ...req.body };
  db.get('teachers').push(teacher).write();
  res.json(teacher);
});

app.put('/api/teachers/:id', authMiddleware, canManage, (req, res) => {
  db.get('teachers').find({ id: req.params.id }).assign(req.body).write();
  res.json({ success: true });
});

app.delete('/api/teachers/:id', authMiddleware, canManage, (req, res) => {
  db.get('teachers').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// رفع Excel للمعلمين
app.post('/api/teachers/upload', authMiddleware, canManage, upload.single('file'), (req, res) => {
  try {
    const wb = XLSX.read(req.file.buffer);
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
    let added = 0, skipped = 0;
    for (const row of rows) {
      const idNumber = String(row['رقم الهوية'] || row['id_number'] || '').trim();
      if (!idNumber || db.get('teachers').find({ idNumber }).value()) { skipped++; continue; }
      const subjectCodes = String(row['المواد'] || row['subjects'] || '').split(',').map(s => s.trim()).filter(Boolean);
      const subjectIds = subjectCodes.map(code => {
        const s = db.get('subjects').find({ courseCode: code }).value();
        return s ? s.id : null;
      }).filter(Boolean);
      db.get('teachers').push({
        id: uuidv4(), idNumber,
        name: row['الاسم'] || row['name'] || '',
        phone: String(row['الجوال'] || row['phone'] || ''),
        email: row['البريد'] || row['email'] || '',
        jobTitle: row['المسمى الوظيفي'] || row['job_title'] || 'محاضر',
        employmentType: row['طبيعة العمل'] || 'دوام كامل',
        approvalStatus: row['حالة الاعتماد'] || 'معتمد',
        available: (row['الحالة'] || row['status'] || 'متاح') === 'متاح',
        maxLoad: parseInt(row['النصاب الأقصى'] || row['max_load'] || 16),
        subjectIds
      }).write();
      added++;
    }
    res.json({ total: rows.length, added, skipped });
  } catch (e) {
    res.status(400).json({ error: 'فشل في قراءة الملف: ' + e.message });
  }
});

// ══════════════════════════════════════════════════
// SECTIONS
// ══════════════════════════════════════════════════
app.get('/api/sections', authMiddleware, (req, res) => {
  let sections = db.get('sections').value();
  const trainees = db.get('trainees').value();
  sections = sections.map(s => ({
    ...s,
    traineeCount: trainees.filter(t => t.sectionId === s.id).length
  }));
  sections.sort((a, b) => a.semester - b.semester || a.part - b.part || a.number.localeCompare(b.number));
  res.json(sections);
});

app.post('/api/sections', authMiddleware, canManage, (req, res) => {
  const section = { id: uuidv4(), traineeCount: 0, ...req.body, createdAt: new Date().toISOString().split('T')[0] };
  db.get('sections').push(section).write();
  res.json(section);
});

app.delete('/api/sections/:id', authMiddleware, canManage, (req, res) => {
  db.get('sections').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// ══════════════════════════════════════════════════
// TRAINEES
// ══════════════════════════════════════════════════
app.get('/api/trainees', authMiddleware, (req, res) => {
  let trainees = db.get('trainees').value();
  if (req.query.sectionId) trainees = trainees.filter(t => t.sectionId === req.query.sectionId);
  res.json(trainees);
});

app.post('/api/trainees', authMiddleware, canManage, (req, res) => {
  const trainee = { id: uuidv4(), status: 'نشط', ...req.body, enrollmentDate: new Date().toISOString().split('T')[0] };
  db.get('trainees').push(trainee).write();
  res.json(trainee);
});

app.put('/api/trainees/:id', authMiddleware, canManage, (req, res) => {
  db.get('trainees').find({ id: req.params.id }).assign(req.body).write();
  res.json({ success: true });
});

app.delete('/api/trainees/:id', authMiddleware, canManage, (req, res) => {
  db.get('trainees').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// رفع Excel للمتدربين
app.post('/api/trainees/upload', authMiddleware, canManage, upload.single('file'), (req, res) => {
  try {
    const wb = XLSX.read(req.file.buffer);
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
    const sendNotifications = req.body.notify === 'true';
    let added = 0, skipped = 0, sectionsCreated = 0, errors = [];
    for (const row of rows) {
      const idNumber = String(row['رقم الهوية'] || row['id_number'] || '').trim();
      if (!idNumber || db.get('trainees').find({ idNumber }).value()) { skipped++; continue; }
      const semester = parseInt(row['الفصل الدراسي'] || row['semester'] || 1);
      const part = parseInt(row['الجزء'] || row['part'] || 1);
      const programId = row['programId'] || db.get('sections').value()[0]?.programId || '1';
      // إيجاد أو إنشاء شعبة
      let section = db.get('sections').find(s => s.semester === semester && s.part === part && s.programId === programId).value();
      if (!section) {
        const sectionCount = db.get('sections').filter(s => s.semester === semester && s.part === part).value().length;
        section = { id: uuidv4(), number: `S${semester}${part}-${sectionCount + 1}`, programId, semester, part, traineeCount: 0, createdAt: new Date().toISOString().split('T')[0] };
        db.get('sections').push(section).write();
        sectionsCreated++;
      }
      db.get('trainees').push({
        id: uuidv4(), idNumber, semester, part,
        name: row['الاسم'] || row['name'] || '',
        email: row['البريد'] || row['email'] || '',
        phone: String(row['الجوال'] || row['phone'] || ''),
        sectionId: section.id,
        status: 'نشط',
        enrollmentDate: new Date().toISOString().split('T')[0]
      }).write();
      added++;
    }
    res.json({ total: rows.length, added, skipped, sectionsCreated, errors, notificationsSent: sendNotifications ? added : 0 });
  } catch (e) {
    res.status(400).json({ error: 'فشل في قراءة الملف: ' + e.message });
  }
});

// ══════════════════════════════════════════════════
// CALENDAR EVENTS
// ══════════════════════════════════════════════════
const DEFAULT_ALERT_DAYS = [14, 7, 1];

app.get('/api/calendar-events', authMiddleware, (req, res) => {
  const events = db.get('calendarEvents').value()
    .sort((a, b) => new Date(a.date) - new Date(b.date));
  const today = new Date();
  const eventsWithStatus = events.map(e => {
    const diff = Math.ceil((new Date(e.date) - today) / (1000 * 60 * 60 * 24));
    let colorClass = diff < 0 ? 'expired' : diff <= 30 ? 'soon' : 'future';
    const alerts = (e.alertDays || DEFAULT_ALERT_DAYS).filter(d => diff >= 0 && diff <= d && diff >= 0);
    return { ...e, daysLeft: diff, colorClass, activeAlerts: alerts };
  });
  res.json(eventsWithStatus);
});

app.post('/api/calendar-events', authMiddleware, canManage, (req, res) => {
  const event = { id: uuidv4(), alertDays: DEFAULT_ALERT_DAYS, ...req.body };
  db.get('calendarEvents').push(event).write();
  res.json(event);
});

app.put('/api/calendar-events/:id', authMiddleware, canManage, (req, res) => {
  db.get('calendarEvents').find({ id: req.params.id }).assign(req.body).write();
  res.json({ success: true });
});

app.delete('/api/calendar-events/:id', authMiddleware, canManage, (req, res) => {
  db.get('calendarEvents').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// ══════════════════════════════════════════════════
// CLASS SYSTEMS
// ══════════════════════════════════════════════════
app.get('/api/class-systems', authMiddleware, (req, res) => {
  res.json(db.get('classSystems').value());
});

app.post('/api/class-systems', authMiddleware, canManage, (req, res) => {
  const maxId = Math.max(...db.get('classSystems').map('id').value(), 10);
  const system = { id: maxId + 1, deletable: true, ...req.body };
  db.get('classSystems').push(system).write();
  res.json(system);
});

app.delete('/api/class-systems/:id', authMiddleware, canManage, (req, res) => {
  const system = db.get('classSystems').find({ id: parseInt(req.params.id) }).value();
  if (!system?.deletable) return res.status(400).json({ error: 'لا يمكن حذف النظام الافتراضي' });
  db.get('classSystems').remove({ id: parseInt(req.params.id) }).write();
  res.json({ success: true });
});

// ══════════════════════════════════════════════════
// SCHEDULE RULES
// ══════════════════════════════════════════════════
app.get('/api/schedule-rules', authMiddleware, (req, res) => {
  res.json(db.get('scheduleRules').value());
});

app.put('/api/schedule-rules/:id', authMiddleware, canManage, (req, res) => {
  db.get('scheduleRules').find({ id: parseInt(req.params.id) }).assign(req.body).write();
  res.json({ success: true });
});

// ══════════════════════════════════════════════════
// SCHEDULE GENERATION ENGINE
// ══════════════════════════════════════════════════
const DAYS = ['الأحد', 'الاثنين', 'الثلاثاء', 'الأربعاء', 'الخميس'];
const PERIODS = [
  { id: 1, start: '17:00', end: '17:40', label: 'الفترة الأولى (5:00-5:40)' },
  { id: 2, start: '17:40', end: '18:20', label: 'الفترة الثانية (5:40-6:20)' },
  { id: 3, start: '18:30', end: '19:10', label: 'الفترة الثالثة (6:30-7:10)' },
  { id: 4, start: '19:10', end: '19:50', label: 'الفترة الرابعة (7:10-7:50)' }
];

function generateSchedule(programId, weekNumber) {
  const sections = db.get('sections').filter({ programId }).value();
  const availableTeachers = db.get('teachers').filter({ available: true, approvalStatus: 'معتمد' }).value();
  const subjects = db.get('subjects').filter({ programId }).value();

  // تتبع الاستخدام
  const teacherSlots = {}; // teacherId -> { day -> Set<periodId> }
  const sectionSlots = {}; // sectionId -> { day -> Set<periodId> }
  const slots = [];

  for (const teacher of availableTeachers) {
    teacherSlots[teacher.id] = {};
    for (const day of DAYS) teacherSlots[teacher.id][day] = new Set();
  }
  for (const section of sections) {
    sectionSlots[section.id] = {};
    for (const day of DAYS) sectionSlots[section.id][day] = new Set();
  }

  let violations = [];

  for (const section of sections) {
    // مواد الشعبة حسب الفصل والجزء
    const sectionSubjects = subjects.filter(s => s.semester === section.semester && s.part === section.part);
    let sessionsPlaced = 0;

    for (const subject of sectionSubjects) {
      // إيجاد معلم يدرس هذه المادة
      const teacher = availableTeachers.find(t =>
        t.subjectIds && t.subjectIds.includes(subject.id)
      );
      if (!teacher) {
        violations.push(`لا يوجد معلم متاح لمادة ${subject.name} في الشعبة ${section.number}`);
        continue;
      }

      const sessionsNeeded = Math.min(subject.weeklyHours, 2);
      let placed = 0;

      for (const day of DAYS) {
        if (placed >= sessionsNeeded) break;
        // قيود يوم الخميس
        const maxPeriod = day === 'الخميس' ? 2 : 4;
        for (let period = 1; period <= maxPeriod; period++) {
          if (placed >= sessionsNeeded) break;
          // فحص عدم التعارض
          if (teacherSlots[teacher.id][day].has(period)) continue;
          if (sectionSlots[section.id][day].has(period)) continue;
          // فحص عدم تكرار المادة في اليوم
          const alreadyThisDay = slots.find(s => s.sectionId === section.id && s.subjectId === subject.id && s.day === day);
          if (alreadyThisDay) continue;
          // حد 4 حصص للمعلم يومياً
          if (teacherSlots[teacher.id][day].size >= 4) continue;

          // تسجيل الحصة
          teacherSlots[teacher.id][day].add(period);
          sectionSlots[section.id][day].add(period);
          slots.push({
            id: uuidv4(),
            sectionId: section.id,
            subjectId: subject.id,
            teacherId: teacher.id,
            day, period,
            weekNumber,
            programId,
            subjectName: subject.name,
            teacherName: teacher.name,
            sectionNumber: section.number,
            periodInfo: PERIODS[period - 1]
          });
          placed++;
          sessionsPlaced++;
        }
      }
    }
  }

  // حفظ الجدول
  db.get('scheduleSlots')
    .remove(s => s.weekNumber === weekNumber && s.programId === programId)
    .write();
  db.get('scheduleSlots').push(...slots).write();

  return { slots, violations, totalSections: sections.length, totalSlots: slots.length };
}

app.post('/api/generate-schedule', authMiddleware, canManage, (req, res) => {
  const { programId, weekNumber } = req.body;
  if (!programId || !weekNumber) return res.status(400).json({ error: 'يجب تحديد البرنامج والأسبوع' });
  const result = generateSchedule(programId, parseInt(weekNumber));
  res.json({ success: true, ...result });
});

// ══════════════════════════════════════════════════
// SCHEDULE VIEW
// ══════════════════════════════════════════════════
app.get('/api/schedule', authMiddleware, (req, res) => {
  let slots = db.get('scheduleSlots').value();
  if (req.query.sectionId) slots = slots.filter(s => s.sectionId === req.query.sectionId);
  if (req.query.teacherId) slots = slots.filter(s => s.teacherId === req.query.teacherId);
  if (req.query.weekNumber) slots = slots.filter(s => s.weekNumber === parseInt(req.query.weekNumber));
  if (req.query.programId) slots = slots.filter(s => s.programId === req.query.programId);
  res.json(slots);
});

// ══════════════════════════════════════════════════
// ATTENDANCE
// ══════════════════════════════════════════════════
app.get('/api/attendance', authMiddleware, (req, res) => {
  let att = db.get('attendance').value();
  if (req.query.sectionId) att = att.filter(a => a.sectionId === req.query.sectionId);
  if (req.query.traineeId) att = att.filter(a => a.traineeId === req.query.traineeId);
  res.json(att);
});

app.post('/api/attendance', authMiddleware, (req, res) => {
  const record = { id: uuidv4(), date: new Date().toISOString().split('T')[0], ...req.body };
  db.get('attendance').push(record).write();
  res.json(record);
});

// ══════════════════════════════════════════════════
// REPORTS
// ══════════════════════════════════════════════════
app.get('/api/reports/overview', authMiddleware, (req, res) => {
  const programs = db.get('programs').value().length;
  const subjects = db.get('subjects').value().length;
  const teachers = db.get('teachers').value().length;
  const availableTeachers = db.get('teachers').filter({ available: true, approvalStatus: 'معتمد' }).value().length;
  const sections = db.get('sections').value().length;
  const trainees = db.get('trainees').filter({ status: 'نشط' }).value().length;
  const scheduledSlots = db.get('scheduleSlots').value().length;
  const calendarEvents = db.get('calendarEvents').value().length;
  const teacherLoad = db.get('teachers').value().map(t => ({
    name: t.name,
    load: db.get('scheduleSlots').filter({ teacherId: t.id }).value().length,
    maxLoad: t.maxLoad
  }));
  res.json({ programs, subjects, teachers, availableTeachers, sections, trainees, scheduledSlots, calendarEvents, teacherLoad });
});

app.get('/api/reports/teacher-load', authMiddleware, (req, res) => {
  const teachers = db.get('teachers').value();
  const data = teachers.map(t => {
    const slots = db.get('scheduleSlots').filter({ teacherId: t.id }).value();
    return {
      id: t.id, name: t.name, approvalStatus: t.approvalStatus, available: t.available,
      currentLoad: slots.length, maxLoad: t.maxLoad,
      percentage: Math.round((slots.length / t.maxLoad) * 100)
    };
  });
  res.json(data);
});

app.get('/api/reports/trainees-by-semester', authMiddleware, (req, res) => {
  const trainees = db.get('trainees').value();
  const result = {};
  for (const t of trainees) {
    const key = `الفصل ${t.semester} - الجزء ${t.part}`;
    result[key] = (result[key] || 0) + 1;
  }
  res.json(result);
});

// ══════════════════════════════════════════════════
// EXCEL TEMPLATES DOWNLOAD
// ══════════════════════════════════════════════════
app.get('/api/templates/:type', authMiddleware, (req, res) => {
  const templates = {
    subjects: [{ course_code: '', name: '', semester: '', part: '', credit_hours: '', weekly_hours: '', lecture_hours: '', practical_hours: '', tutorial_hours: '', prerequisite: '' }],
    teachers: [{ 'رقم الهوية': '', 'الاسم': '', 'الجوال': '', 'البريد': '', 'المسمى الوظيفي': '', 'طبيعة العمل': 'دوام كامل', 'حالة الاعتماد': 'معتمد', 'الحالة': 'متاح', 'النصاب الأقصى': 16, 'المواد': '' }],
    trainees: [{ 'الاسم': '', 'البريد': '', 'الجوال': '', 'رقم الهوية': '', 'الفصل الدراسي': '', 'الجزء': '' }]
  };
  const data = templates[req.params.type];
  if (!data) return res.status(404).json({ error: 'قالب غير موجود' });
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(data), 'البيانات');
  const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename=template_${req.params.type}.xlsx`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buffer);
});

// ══════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`✅ TMS Server running on http://localhost:${PORT}`);
  console.log(`📋 حسابات الدخول: admin/manager/dataentry/teacher/trainee@center.sa — كلمة المرور: 123456`);
});
