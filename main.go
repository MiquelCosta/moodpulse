package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	kMin = 5
)

var appAdminPassword string

var allowedTags = map[string]bool{
	"carga": true, "herramientas": true, "procesos": true,
	"ambiente": true, "personal": true,
}

type App struct {
	db   *sql.DB
	tpl  *template.Template
	sess map[string]time.Time
}

func main() {
	// Secrets / config
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("Missing DATABASE_URL env var")
	}
	appAdminPassword = os.Getenv("ADMIN_PASSWORD")
	if appAdminPassword == "" {
		log.Fatal("Missing ADMIN_PASSWORD env var")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// DB
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// quick connectivity check
	if err := db.Ping(); err != nil {
		log.Fatalf("DB ping failed: %v", err)
	}

	initDB(db)

	tpl := template.Must(template.New("all").Parse(baseHTML + homeHTML + loginHTML + adminHTML))

	app := &App{
		db:   db,
		tpl:  tpl,
		sess: map[string]time.Time{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.home)
	mux.HandleFunc("/submit", app.submit)
	mux.HandleFunc("/admin", app.admin)
	mux.HandleFunc("/admin/login", app.adminLogin)
	mux.HandleFunc("/admin/logout", app.adminLogout)

	log.Println("MoodPulse running on http://0.0.0.0:" + port)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, noStore(mux)))
}

func initDB(db *sql.DB) {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS mood_entries (
		id TEXT PRIMARY KEY,
		created_at TIMESTAMPTZ NOT NULL,
		week_start DATE NOT NULL,
		score INTEGER NOT NULL CHECK (score BETWEEN 1 AND 5),
		tags_json JSONB NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_week_start ON mood_entries(week_start);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	week := isoWeekStart(time.Now()).Format("2006-01-02")
	sent := r.URL.Query().Get("sent")

	data := map[string]any{
		"WeekStart": week,
		"Tags":      sortedTags(),
		"Sent":      sent,
	}

	_ = a.tpl.ExecuteTemplate(w, "home", data)
}

func (a *App) submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	scoreStr := strings.TrimSpace(r.FormValue("score"))
	if len(scoreStr) != 1 || scoreStr[0] < '1' || scoreStr[0] > '5' {
		http.Error(w, "invalid score", http.StatusBadRequest)
		return
	}
	score := int(scoreStr[0] - '0')

	// tags: allowlist, unique, max 2
	inTags := r.Form["tags"]
	seen := map[string]bool{}
	tags := make([]string, 0, 2)
	for _, t := range inTags {
		t = strings.TrimSpace(strings.ToLower(t))
		if !allowedTags[t] || seen[t] {
			continue
		}
		seen[t] = true
		tags = append(tags, t)
		if len(tags) == 2 {
			break
		}
	}
	tagsJSON, _ := json.Marshal(tags)

	id := randHex(16)
	createdAt := time.Now().UTC()
	weekStart := isoWeekStart(time.Now()).Format("2006-01-02")

	_, err := a.db.Exec(
		`INSERT INTO mood_entries (id, created_at, week_start, score, tags_json)
		 VALUES ($1,$2,$3,$4,$5)`,
		id, createdAt, weekStart, score, string(tagsJSON),
	)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/?sent=1", http.StatusSeeOther)
}

func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !a.authed(r) {
		_ = a.tpl.ExecuteTemplate(w, "login", map[string]any{"Error": ""})
		return
	}

	weeks, err := a.weeklySummary(8)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"KMin":  kMin,
		"Weeks": weeks,
	}
	_ = a.tpl.ExecuteTemplate(w, "admin", data)
}

func (a *App) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	pass := r.FormValue("password")
	if pass != appAdminPassword {
		_ = a.tpl.ExecuteTemplate(w, "login", map[string]any{"Error": "Password incorrecto"})
		return
	}

	token := randHex(24)
	a.sess[token] = time.Now().Add(24 * time.Hour)

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Si vas con HTTPS (deberías), puedes activar Secure:
		// Secure: true,
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) adminLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie("admin_session")
	if err != nil || c.Value == "" {
		return false
	}
	exp, ok := a.sess[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.sess, c.Value)
		return false
	}
	return true
}

type WeekSummary struct {
	WeekStart string
	N         int
	Safe      bool
	Avg       float64
	Dist      map[int]int
	Tags      map[string]int
}

func (a *App) weeklySummary(lastN int) ([]WeekSummary, error) {
	start := isoWeekStart(time.Now()).AddDate(0, 0, -7*(lastN-1))
	startStr := start.Format("2006-01-02")

	rows, err := a.db.Query(
		`SELECT week_start, score, tags_json
		 FROM mood_entries
		 WHERE week_start >= $1
		 ORDER BY week_start ASC`,
		startStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type bucket struct {
		sum  int
		n    int
		dist map[int]int
		tags map[string]int
	}
	b := map[string]*bucket{}

	for rows.Next() {
		var ws time.Time
		var score int
		var tagsJSON string
		if err := rows.Scan(&ws, &score, &tagsJSON); err != nil {
			return nil, err
		}
		key := ws.Format("2006-01-02")

		if _, ok := b[key]; !ok {
			b[key] = &bucket{
				dist: map[int]int{1: 0, 2: 0, 3: 0, 4: 0, 5: 0},
				tags: map[string]int{},
			}
		}
		b[key].n++
		b[key].sum += score
		b[key].dist[score]++

		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		for _, t := range tags {
			b[key].tags[t]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	weeks := make([]string, 0, len(b))
	for k := range b {
		weeks = append(weeks, k)
	}
	sort.Strings(weeks)

	out := make([]WeekSummary, 0, len(weeks))
	for _, ws := range weeks {
		bk := b[ws]
		safe := bk.n >= kMin
		if !safe {
			out = append(out, WeekSummary{WeekStart: ws, N: bk.n, Safe: false})
			continue
		}
		avg := 0.0
		if bk.n > 0 {
			avg = float64(bk.sum) / float64(bk.n)
		}
		out = append(out, WeekSummary{
			WeekStart: ws,
			N:         bk.n,
			Safe:      true,
			Avg:       round2(avg),
			Dist:      bk.dist,
			Tags:      bk.tags,
		})
	}

	return out, nil
}

func isoWeekStart(t time.Time) time.Time {
	tt := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
	wd := int(tt.Weekday())
	if wd == 0 {
		wd = 7
	}
	return tt.AddDate(0, 0, -(wd - 1)) // lunes
}

func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sortedTags() []string {
	t := make([]string, 0, len(allowedTags))
	for k := range allowedTags {
		t = append(t, k)
	}
	sort.Strings(t)
	return t
}

func round2(x float64) float64 {
	return float64(int(x*100+0.5)) / 100
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

const baseHTML = `
{{define "base_home"}}
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mood Pulse</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;}
  .card{border:1px solid #ddd;border-radius:16px;padding:16px;margin:12px 0;}
  .row{display:flex;gap:10px;flex-wrap:wrap;}
  button{border-radius:12px;border:1px solid #111;padding:12px 14px;background:#fff;cursor:pointer}
  .primary{background:#111;color:#fff}
  .muted{color:#666;font-size:12px}
  a{color:#111}
  input[type="password"]{padding:10px;border-radius:10px;border:1px solid #aaa;width:220px}
</style>
</head>
<body>
{{template "content_home" .}}
</body>
</html>
{{end}}

{{define "base_login"}}
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mood Pulse</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;}
  .card{border:1px solid #ddd;border-radius:16px;padding:16px;margin:12px 0;}
  .row{display:flex;gap:10px;flex-wrap:wrap;}
  button{border-radius:12px;border:1px solid #111;padding:12px 14px;background:#fff;cursor:pointer}
  .primary{background:#111;color:#fff}
  .muted{color:#666;font-size:12px}
  a{color:#111}
  input[type="password"]{padding:10px;border-radius:10px;border:1px solid #aaa;width:220px}
</style>
</head>
<body>
{{template "content_login" .}}
</body>
</html>
{{end}}

{{define "base_admin"}}
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mood Pulse</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:760px;margin:32px auto;padding:0 16px;}
  .card{border:1px solid #ddd;border-radius:16px;padding:16px;margin:12px 0;}
  .row{display:flex;gap:10px;flex-wrap:wrap;}
  button{border-radius:12px;border:1px solid #111;padding:12px 14px;background:#fff;cursor:pointer}
  .primary{background:#111;color:#fff}
  .muted{color:#666;font-size:12px}
  a{color:#111}
  input[type="password"]{padding:10px;border-radius:10px;border:1px solid #aaa;width:220px}
</style>
</head>
<body>
{{template "content_admin" .}}
</body>
</html>
{{end}}
`

const homeHTML = `
{{define "home"}}
{{template "base_home" .}}
{{end}}

{{define "content_home"}}
<h1>Mood Pulse</h1>

<div class="card">
  <h2>¿Cómo ha ido tu semana?</h2>

  {{if eq .Sent "1"}}
    <p>Gracias. Check-in enviado.</p>
  {{end}}

  <form method="post" action="/submit">
    <div class="row" style="margin:10px 0">
      <label><input type="radio" name="score" value="1" required> 1 😣</label>
      <label><input type="radio" name="score" value="2"> 2 🙁</label>
      <label><input type="radio" name="score" value="3"> 3 😐</label>
      <label><input type="radio" name="score" value="4"> 4 🙂</label>
      <label><input type="radio" name="score" value="5"> 5 😄</label>
    </div>

    <h3 style="margin:10px 0 6px 0;font-size:16px">¿Qué ha influido? (opcional, máximo 2)</h3>
    <div class="row">
      {{range $t := .Tags}}
        <label><input type="checkbox" name="tags" value="{{$t}}"> {{$t}}</label>
      {{end}}
    </div>

    <div style="margin-top:14px">
      <button class="primary" type="submit">Enviar</button>
    </div>

    <p class="muted" style="margin-top:12px">
      Privacidad: no pedimos nombre ni email. RRHH solo ve agregados semanales si hay suficientes respuestas.
    </p>
  </form>
</div>

<p class="muted">Semana actual (inicio lunes): {{.WeekStart}}</p>
<p><a href="/admin">Acceso RRHH</a></p>

<script>
  const checks = Array.from(document.querySelectorAll('input[type="checkbox"][name="tags"]'));
  checks.forEach(ch => ch.addEventListener('change', () => {
    const on = checks.filter(x => x.checked);
    if (on.length > 2) ch.checked = false;
  }));

  const wk = "{{.WeekStart}}";
  const key = "mood_sent_" + wk;
  const url = new URL(window.location.href);
  if (url.searchParams.get("sent") === "1") localStorage.setItem(key, "1");
  if (localStorage.getItem(key) === "1") {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Este navegador ya envió un check-in esta semana.";
    document.querySelector(".card").prepend(p);
  }
</script>
{{end}}
`

const loginHTML = `
{{define "login"}}
{{template "base_login" .}}
{{end}}

{{define "content_login"}}
<h1>RRHH</h1>
<div class="card">
  <h2>Login</h2>
  {{if .Error}}<p style="color:#b00">{{.Error}}</p>{{end}}
  <form method="post" action="/admin/login">
    <label>Password<br><input type="password" name="password"></label>
    <div style="margin-top:12px">
      <button class="primary" type="submit">Entrar</button>
      <a style="margin-left:10px" href="/">Volver</a>
    </div>
  </form>
</div>
{{end}}
`

const adminHTML = `
{{define "admin"}}
{{template "base_admin" .}}
{{end}}

{{define "content_admin"}}
<h1>RRHH</h1>
<p><a href="/admin/logout">Cerrar sesión</a> · <a href="/">Vista plantilla</a></p>

<div class="card">
  <h2>Resumen (k={{.KMin}})</h2>

  {{range .Weeks}}
    <div class="card">
      <strong>Semana {{.WeekStart}}</strong><br>
      Respuestas: {{.N}}<br>

      {{if .Safe}}
        Media: {{printf "%.2f" .Avg}}<br>
        Distribución: 1={{index .Dist 1}} 2={{index .Dist 2}} 3={{index .Dist 3}} 4={{index .Dist 4}} 5={{index .Dist 5}}<br>
        Tags:
        {{range $k,$v := .Tags}} {{$k}}={{$v}} {{end}}
      {{else}}
        <em>Muestra incompleta (no se muestran detalles)</em>
      {{end}}
    </div>
  {{end}}
</div>

<p class="muted">Consejo: usa HTTPS y password fuerte.</p>
{{end}}
`
