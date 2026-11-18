export const environment = {
  // v04: the production build is served by the SAME Databricks App process as the /api/* routes
  // (rg/api.py, via a FastAPI StaticFiles mount - see app.py), so API calls stay same-origin/relative,
  // same as dev.
  apiBase: '',
};
