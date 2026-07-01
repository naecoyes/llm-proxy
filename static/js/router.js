export class Router {
  constructor(routes, onRoute) {
    this.routes = routes;
    this.onRoute = onRoute;
    this.current = null;
    this.handler = () => this.navigate(this.routeFromHash(), false);
  }

  routeFromHash() {
    const route = window.location.hash.replace(/^#\/?/, "").split("?")[0];
    return this.routes[route] ? route : "overview";
  }

  start() {
    window.addEventListener("hashchange", this.handler);
    this.navigate(this.routeFromHash(), false);
  }

  navigate(route, updateHash = true) {
    const next = this.routes[route] ? route : "overview";
    if (updateHash && window.location.hash !== `#${next}`) {
      window.location.hash = next;
      return;
    }
    this.current = next;
    this.onRoute(next, this.routes[next]);
  }
}
