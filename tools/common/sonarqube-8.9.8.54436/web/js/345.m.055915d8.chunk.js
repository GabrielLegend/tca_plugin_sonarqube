(window.webpackJsonp=window.webpackJsonp||[]).push([[345],{1851:function(e,t,a){"use strict";a.r(t),a.d(t,"default",(function(){return re}));var n=a(2),s=a(31),r=a(550),i=a(437),c=a(312),o=a(407),l=a.n(o),p=a(349),h=a.n(p),d=a(374),m=a.n(d),u=a(394),b=a.n(u),j=a(1429),f=a.n(j),g=a(332),O=a.n(g),E=a(319),y=a.n(E),v=a(340),P=a.n(v),C=a(346),S=a.n(C),k=a(591),N=a.n(k),w=a(338),B=a.n(w),_=a(348),D=a.n(_),U=a(317),M=a.n(U),x=a(345),F=a.n(x),R=a(625);class A extends n.PureComponent{constructor(){super(...arguments),this.handleMouseDown=e=>{e.preventDefault(),e.stopPropagation(),this.props.onSelect(this.props.option,e)},this.handleMouseEnter=e=>{this.props.onFocus(this.props.option,e)},this.handleMouseMove=e=>{this.props.isFocused||this.props.onFocus(this.props.option,e)}}render(){const{option:e}=this.props;return n.createElement(M.a,{overlay:e.label,placement:"left"},n.createElement("div",{className:this.props.className,onMouseDown:this.handleMouseDown,onMouseEnter:this.handleMouseEnter,onMouseMove:this.handleMouseMove,role:"listitem"},n.createElement("div",null,n.createElement(l.a,{className:"little-spacer-right"}),e.label)))}}class T extends n.PureComponent{constructor(){super(...arguments),this.node=null,this.mounted=!1,this.state={loading:!1},this.parseBranches=e=>N()(e,[e=>e.isMain,e=>e.name]).map(e=>({value:e.name,label:e.name,isMain:e.isMain})),this.setCurrentTarget=e=>{this.node=e.target},this.handleChange=e=>{this.props.onChange(this.props.project.key,e),this.setState({selectedBranch:e})},this.handleOpen=()=>{if(this.state.branches&&this.node)return void this.props.onOpen(this.node,this.state.branches.length);const{project:e}=this.props;this.setState({loading:!0}),Object(R.d)(e.key).then(e=>{const t=this.parseBranches(e);this.node&&this.props.onOpen(this.node,t.length),this.mounted&&this.setState({branches:t,loading:!1})},()=>{})}}componentDidMount(){this.mounted=!0}componentWillUnmount(){this.mounted=!1}render(){const{checked:e,onCheck:t,onClose:a,project:s}=this.props,r=this.state.branches||[{value:s.branch,label:s.branch,isMain:s.isMain}],i=s.enabled?this.state.selectedBranch||s.branch:this.state.selectedBranch;return n.createElement("tr",{key:s.key},n.createElement("td",{className:"text-center"},n.createElement(B.a,{checked:e,id:s.key,onCheck:t})),n.createElement("td",{className:"nowrap hide-overflow branch-name-row"},n.createElement(M.a,{overlay:s.name},n.createElement("span",null,n.createElement(F.a,{qualifier:"TRK"})," ",s.name))),n.createElement("td",null,n.createElement(D.a,{className:"width100",clearable:!1,disabled:!e,onChange:this.handleChange,onClose:a,onFocus:this.setCurrentTarget,onOpen:this.handleOpen,optionComponent:A,options:r,searchable:!1,value:i}),n.createElement(y.a,{className:"project-branch-row-spinner",loading:this.state.loading})))}}function L(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function q(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?L(Object(a),!0).forEach((function(t){J(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):L(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function J(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}class K extends n.PureComponent{constructor(){super(...arguments),this.mounted=!1,this.node=null,this.currentSelect=null,this.state={loading:!1,name:"",projects:[],selected:[],selectedBranches:{}},this.stopLoading=()=>{this.mounted&&this.setState({loading:!1})},this.canSubmit=()=>{const e=f()(this.state.selectedBranches,(e,t)=>!e&&this.state.selected.includes(t));return!this.state.loading&&this.state.name.length>0&&!e&&this.state.selected.length>0},this.handleInputChange=e=>{this.setState({name:e.currentTarget.value})},this.handleFormSubmit=async()=>{const e=this.state.selected,t=e.map(e=>{const t=this.state.selectedBranches[e];return!t||t.isMain?"":t.value});this.props.branch?(await Object(r.l)({application:this.props.application.key,branch:this.props.branch.name,name:this.state.name,project:e,projectBranch:t}),this.props.onUpdate&&this.props.onUpdate(this.state.name)):(await Object(r.a)({application:this.props.application.key,branch:this.state.name,project:e,projectBranch:t}),this.props.onCreate&&this.props.onCreate({name:this.state.name,isMain:!1})),this.props.onClose()},this.handleProjectCheck=(e,t)=>{this.setState(a=>({selected:e?[...a.selected,t]:h()(a.selected,t)}))},this.handleBranchChange=(e,t)=>{this.setState(a=>({selectedBranches:q({},a.selectedBranches,{[e]:t})}))},this.handleSelectorClose=()=>{this.node&&this.node.classList.add("selector-hidden")},this.handleSelectorDirection=(e,t)=>{if(this.node){const a=this.node.getBoundingClientRect().top,n=this.node.offsetHeight,s=Math.min(220,22*(t+1));e.getBoundingClientRect().top+s>a+n?this.node.classList.add("inverted-direction"):this.node.classList.remove("inverted-direction"),this.node.classList.remove("selector-hidden")}},this.renderProjectsList=()=>n.createElement(n.Fragment,null,n.createElement("strong",{className:"spacer-left spacer-top"},Object(s.translate)("application_console.branches.configuration")),n.createElement("p",{className:"spacer-top big-spacer-bottom spacer-left spacer-right"},Object(s.translate)("application_console.branches.create.help")),n.createElement("table",{className:"data zebra"},n.createElement("thead",null,n.createElement("tr",null,n.createElement("th",{className:"thin"}),n.createElement("th",{className:"thin"},Object(s.translate)("project")),n.createElement("th",null,Object(s.translate)("branch")))),n.createElement("tbody",null,this.state.projects.map(e=>n.createElement(T,{checked:this.state.selected.includes(e.key),key:e.key,onChange:this.handleBranchChange,onCheck:this.handleProjectCheck,onClose:this.handleSelectorClose,onOpen:this.handleSelectorDirection,project:e})))))}componentDidMount(){this.mounted=!0;const{application:e}=this.props,t=this.props.branch?this.props.branch.name:void 0;this.setState({loading:!0}),Object(r.g)(e.key,t).then(({projects:e})=>{if(this.mounted){const a=e.filter(e=>this.props.enabledProjectsKey.includes(e.key)),n=a.filter(e=>e.selected).map(e=>e.key),s={};a.forEach(e=>{e.enabled?s[e.key]={value:e.branch||"",label:e.branch||"",isMain:e.isMain||!1}:s[e.key]=null}),this.setState({name:t||"",selected:n,loading:!1,projects:a,selectedBranches:s})}},()=>{this.props.onClose()})}componentWillUnmount(){this.mounted=!1}render(){const e=void 0!==this.props.branch,t=Object(s.translate)("application_console.branches",e?"update":"create");return n.createElement(O.a,{header:t,onClose:this.props.onClose,onSubmit:this.handleFormSubmit,size:"medium"},({onCloseClick:a,onFormSubmit:r,submitting:i})=>n.createElement("form",{className:"views-form",onSubmit:r},n.createElement("div",{className:"modal-head"},n.createElement("h2",null,t)),n.createElement("div",{className:"modal-body modal-container selector-hidden",ref:e=>this.node=e},this.state.loading?n.createElement("div",{className:"text-center big-spacer-top big-spacer-bottom"},n.createElement("i",{className:"spinner spacer-right"})):n.createElement(n.Fragment,null,n.createElement(S.a,{className:"modal-field"}),n.createElement("div",{className:"modal-field"},n.createElement("label",{htmlFor:"view-edit-name"},Object(s.translate)("name"),n.createElement(P.a,null)),n.createElement("input",{autoFocus:!0,className:"input-super-large",maxLength:250,name:"name",onChange:this.handleInputChange,size:50,type:"text",value:this.state.name})),this.renderProjectsList())),n.createElement("div",{className:"modal-foot"},n.createElement(y.a,{className:"spacer-right",loading:i}),n.createElement(c.SubmitButton,{disabled:i||!this.canSubmit()},Object(s.translate)("application_console.branches",e?"update":"create","verb")),n.createElement(c.ResetButtonLink,{onClick:a},Object(s.translate)("application_console.branches.cancel")))))}}class z extends n.PureComponent{constructor(){super(...arguments),this.state={isUpdating:!1},this.handleDelete=()=>{const{application:e,branch:t}=this.props;return Object(r.e)(e.key,t.name).then(()=>{this.props.onUpdateBranches(h()(e.branches,t))})},this.handleUpdate=e=>{this.props.onUpdateBranches(this.props.application.branches.map(t=>(t.name===this.props.branch.name&&(t.name=e),t)))},this.handleCloseForm=()=>{this.setState({isUpdating:!1})},this.handleUpdateClick=()=>{this.setState({isUpdating:!0})}}render(){return n.createElement(n.Fragment,null,n.createElement(b.a,{confirmButtonText:Object(s.translate)("delete"),isDestructive:!0,modalBody:Object(s.translateWithParameters)("application_console.branches.delete.warning_x",this.props.branch.name),modalHeader:Object(s.translate)("application_console.branches.delete"),onConfirm:this.handleDelete},({onClick:e})=>n.createElement(m.a,null,n.createElement(d.ActionsDropdownItem,{onClick:this.handleUpdateClick},Object(s.translate)("edit")),n.createElement(d.ActionsDropdownItem,{destructive:!0,onClick:e},Object(s.translate)("delete")))),this.state.isUpdating&&n.createElement(K,{application:this.props.application,branch:this.props.branch,enabledProjectsKey:this.props.application.projects.filter(e=>e.enabled).map(e=>e.key),onClose:this.handleCloseForm,onUpdate:this.handleUpdate}))}}function W(e){const{application:t,branch:a}=e;return n.createElement("tr",null,n.createElement("td",null,n.createElement(l.a,{className:"little-spacer-right"}),a.name,a.isMain&&n.createElement("span",{className:"badge spacer-left"},Object(s.translate)("application_console.branches.main_branch"))),n.createElement("td",{className:"thin nowrap"},!a.isMain&&n.createElement(z,{application:t,branch:a,onUpdateBranches:e.onUpdateBranches})))}class I extends n.PureComponent{constructor(){super(...arguments),this.state={creating:!1},this.handleCreate=e=>{this.props.onUpdateBranches([...this.props.application.branches,e])},this.handleCreateFormClose=()=>{this.setState({creating:!1})},this.handleCreateClick=()=>{this.setState({creating:!0})},this.canCreateBranches=()=>this.props.application.projects&&this.props.application.projects.some(e=>Boolean(e.enabled))}renderBranches(e){const{application:t}=this.props;return e?n.createElement("div",{className:"app-branches-list"},n.createElement("table",{className:"data zebra"},n.createElement("tbody",null,t.branches.map(e=>n.createElement(W,{application:t,branch:e,key:e.name,onUpdateBranches:this.props.onUpdateBranches}))))):n.createElement("div",{className:"app-branches-list"},n.createElement("p",{className:"text-center big-spacer-top"},Object(s.translate)("application_console.branches.no_branches")))}render(){const{application:e}=this.props,t=this.canCreateBranches();return n.createElement("div",{className:"app-branches-console"},n.createElement("div",{className:"boxed-group-actions"},n.createElement(c.Button,{disabled:!t,onClick:this.handleCreateClick},Object(s.translate)("application_console.branches.create"))),n.createElement("h2",{className:"text-limited big-spacer-top",title:Object(s.translate)("application_console.branches")},Object(s.translate)("application_console.branches")),n.createElement("p",null,Object(s.translate)("application_console.branches.help")),this.renderBranches(t),this.state.creating&&n.createElement(K,{application:e,enabledProjectsKey:e.projects.map(e=>e.key),onClose:this.handleCreateFormClose,onCreate:this.handleCreate}))}}var H=a(490),G=a.n(H),Q=a(470),V=a.n(Q);function X(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function Y(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?X(Object(a),!0).forEach((function(t){Z(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):X(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function Z(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}class $ extends n.PureComponent{constructor(e){super(e),this.mounted=!1,this.loadApplicationProjects=e=>Object(r.i)({application:this.state.lastSearchParams.applicationKey,p:e.page,ps:e.pageSize,q:""!==e.query?e.query:void 0,selected:e.filter}),this.fetchProjects=e=>this.loadApplicationProjects(e).then(t=>{this.mounted&&this.setState(a=>{const n=null!=e.page&&e.page>1,{projects:s,selectedProjects:r,disabledProjects:i}=this.dealWithProjects(t,n,a);return{disabledProjects:i,lastSearchParams:Y({},a.lastSearchParams,{},e),needToReload:!1,projects:s,projectsTotalCount:t.paging.total,selectedProjects:r}})}),this.dealWithProjects=(e,t,a)=>{const n=t?[...a.projects,...e.projects]:e.projects,s=e.projects.filter(e=>e.selected).map(e=>e.key),r=t?[...a.selectedProjects,...s]:s;return{disabledProjects:t?[...a.disabledProjects]:[],projects:n,selectedProjects:r}},this.handleSelect=e=>Object(r.b)(this.props.application.key,e).then(()=>{this.mounted&&this.setState(t=>{const a=t.projects.find(t=>t.key===e);return a&&this.props.onAddProject&&this.props.onAddProject(a),{needToReload:!0,selectedProjects:[...t.selectedProjects,e]}})}),this.handleUnselect=e=>Object(r.k)(this.props.application.key,e).then(()=>{this.mounted&&this.setState(t=>(this.props.onRemoveProject&&this.props.onRemoveProject(e),{needToReload:!0,selectedProjects:h()(t.selectedProjects,e)}))}),this.renderElement=e=>{const t=G()(this.state.projects,{key:e});return void 0===t?"":n.createElement("div",{className:"views-project-item display-flex-center"},n.createElement(F.a,{className:"spacer-right",qualifier:"TRK"}),n.createElement("div",null,n.createElement("div",{title:t.name},t.name),n.createElement("div",{className:"note"},t.key)))},this.state={disabledProjects:[],lastSearchParams:{applicationKey:e.application.key,query:"",filter:Q.SelectListFilter.Selected},needToReload:!1,projects:[],selectedProjects:[]}}componentDidMount(){this.mounted=!0}componentDidUpdate(e){e.application.key!==this.props.application.key&&this.setState(e=>({lastSearchParams:Y({},e.lastSearchParams,{applicationKey:this.props.application.key})}),()=>this.fetchProjects(this.state.lastSearchParams))}componentWillUnmount(){this.mounted=!1}render(){const{projects:e,selectedProjects:t}=this.state;return n.createElement(V.a,{disabledElements:this.state.disabledProjects,elements:e.map(e=>e.key),elementsTotalCount:this.state.projectsTotalCount,needToReload:this.state.needToReload&&this.state.lastSearchParams&&this.state.lastSearchParams.filter!==Q.SelectListFilter.All,onSearch:this.fetchProjects,onSelect:this.handleSelect,onUnselect:this.handleUnselect,renderElement:this.renderElement,selectedElements:t,withPaging:!0})}}class ee extends n.PureComponent{constructor(e){super(e),this.handleNameChange=e=>{this.setState({name:e.currentTarget.value})},this.handleDescriptionChange=e=>{this.setState({description:e.currentTarget.value})},this.handleFormSubmit=async()=>{await this.props.onEdit(this.state.name,this.state.description),this.props.onClose()},this.state={description:e.application.description||"",name:e.application.name}}render(){return n.createElement(O.a,{header:this.props.header,onClose:this.props.onClose,onSubmit:this.handleFormSubmit,size:"small"},({onCloseClick:e,onFormSubmit:t,submitting:a})=>n.createElement("form",{onSubmit:t},n.createElement("div",{className:"modal-head"},n.createElement("h2",null,this.props.header)),n.createElement("div",{className:"modal-body"},n.createElement("div",{className:"modal-field"},n.createElement("label",{htmlFor:"view-edit-name"},Object(s.translate)("name")),n.createElement("input",{autoFocus:!0,id:"view-edit-name",maxLength:100,name:"name",onChange:this.handleNameChange,size:50,type:"text",value:this.state.name})),n.createElement("div",{className:"modal-field"},n.createElement("label",{htmlFor:"view-edit-description"},Object(s.translate)("description")),n.createElement("textarea",{id:"view-edit-description",name:"description",onChange:this.handleDescriptionChange,value:this.state.description}))),n.createElement("div",{className:"modal-foot"},n.createElement(y.a,{className:"spacer-right",loading:a}),n.createElement(c.SubmitButton,{disabled:a||!this.state.name.length},Object(s.translate)("save")),n.createElement(c.ResetButtonLink,{onClick:e},Object(s.translate)("cancel")))))}}function te(e){const[t,a]=n.useState(!1),{application:r,loading:i}=e;return i?n.createElement("i",{className:"spinner spacer"}):n.createElement("div",{className:"page page-limited"},n.createElement("div",{className:"boxed-group",id:"view-details"},n.createElement("div",{className:"boxed-group-actions"},n.createElement(c.Button,{className:"little-spacer-right",id:"view-details-edit",onClick:()=>a(!0)},Object(s.translate)("edit")),n.createElement(c.Button,{className:"little-spacer-right",onClick:e.onRefresh},Object(s.translate)("application_console.recompute"))),n.createElement("header",{className:"boxed-group-header",id:"view-details-header"},n.createElement("h2",{className:"text-limited",title:r.name},r.name)),n.createElement("div",{className:"boxed-group-inner",id:"view-details-content"},n.createElement("div",{className:"big-spacer-bottom"},r.description&&n.createElement("div",{className:"little-spacer-bottom"},r.description),n.createElement("div",{className:"subtitle"},Object(s.translate)("key"),": ",r.key)),n.createElement($,{onAddProject:e.onAddProject,onRemoveProject:e.onRemoveProject,application:r}),n.createElement(I,{application:r,onUpdateBranches:e.onUpdateBranches})),t&&n.createElement(ee,{header:Object(s.translate)("portfolios.edit_application"),onClose:()=>a(!1),onEdit:e.onEdit,application:r})))}function ae(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function ne(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?ae(Object(a),!0).forEach((function(t){se(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):ae(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function se(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}class re extends n.PureComponent{constructor(){super(...arguments),this.mounted=!1,this.state={loading:!1},this.updateApplicationState=e=>{this.setState(t=>t.application?{application:ne({},t.application,{},e(t.application))}:null)},this.fetchDetails=async()=>{try{const e=await Object(r.g)(this.props.component.key);this.mounted&&this.setState({application:e,loading:!1})}catch(e){this.mounted&&this.setState({loading:!1})}},this.handleRefreshClick=async()=>{this.state.application&&(await Object(r.j)(this.state.application.key),Object(i.a)(Object(s.translate)("application_console.refresh_started")))},this.handleEdit=async(e,t)=>{this.state.application&&await Object(r.f)(this.state.application.key,e,t),this.mounted&&this.updateApplicationState(()=>({name:e,description:t}))},this.handleAddProject=e=>{this.updateApplicationState(t=>({projects:[...t.projects,e]}))},this.handleRemoveProject=e=>{this.updateApplicationState(t=>({projects:t.projects.filter(t=>t.key!==e)}))},this.handleUpdateBranches=e=>{this.updateApplicationState(()=>({branches:e}))}}componentDidMount(){this.mounted=!0,this.fetchDetails()}componentDidUpdate(e){e.component.key!==this.props.component.key&&this.fetchDetails()}componentWillUnmount(){this.mounted=!1}render(){const{application:e,loading:t}=this.state;return e?n.createElement(te,{loading:t,application:e,onAddProject:this.handleAddProject,onEdit:this.handleEdit,onRefresh:this.handleRefreshClick,onRemoveProject:this.handleRemoveProject,onUpdateBranches:this.handleUpdateBranches}):null}}},437:function(e,t,a){"use strict";a.d(t,"a",(function(){return r}));var n=a(416),s=a(414);function r(e){Object(s.default)().dispatch(n.b(e))}},550:function(e,t,a){"use strict";a.d(t,"h",(function(){return r})),a.d(t,"g",(function(){return i})),a.d(t,"a",(function(){return c})),a.d(t,"l",(function(){return o})),a.d(t,"e",(function(){return l})),a.d(t,"i",(function(){return p})),a.d(t,"b",(function(){return h})),a.d(t,"k",(function(){return d})),a.d(t,"j",(function(){return m})),a.d(t,"c",(function(){return u})),a.d(t,"d",(function(){return b})),a.d(t,"f",(function(){return j}));var n=a(9),s=a(324);function r(e,t){return Object(n.getJSON)("/api/applications/show_leak",{application:e,branch:t}).then(e=>e.leaks,s.a)}function i(e,t){return Object(n.getJSON)("/api/applications/show",{application:e,branch:t}).then(e=>e.application,s.a)}function c(e){return Object(n.post)("/api/applications/create_branch",e).catch(s.a)}function o(e){return Object(n.post)("/api/applications/update_branch",e).catch(s.a)}function l(e,t){return Object(n.post)("/api/applications/delete_branch",{application:e,branch:t}).catch(s.a)}function p(e){return Object(n.getJSON)("/api/applications/search_projects",e).catch(s.a)}function h(e,t){return Object(n.post)("/api/applications/add_project",{application:e,project:t}).catch(s.a)}function d(e,t){return Object(n.post)("/api/applications/remove_project",{application:e,project:t}).catch(s.a)}function m(e){return Object(n.post)("/api/applications/refresh",{key:e}).catch(s.a)}function u(e,t,a,r){return Object(n.postJSON)("/api/applications/create",{description:t,key:a,name:e,visibility:r}).catch(s.a)}function b(e){return Object(n.post)("/api/applications/delete",{application:e}).catch(s.a)}function j(e,t,a){return Object(n.post)("/api/applications/update",{name:t,description:a,application:e}).catch(s.a)}},625:function(e,t,a){"use strict";a.d(t,"d",(function(){return r})),a.d(t,"e",(function(){return i})),a.d(t,"a",(function(){return c})),a.d(t,"b",(function(){return o})),a.d(t,"f",(function(){return l})),a.d(t,"c",(function(){return p}));var n=a(9),s=a(324);function r(e){return Object(n.getJSON)("/api/project_branches/list",{project:e}).then(e=>e.branches,s.a)}function i(e){return Object(n.getJSON)("/api/project_pull_requests/list",{project:e}).then(e=>e.pullRequests,s.a)}function c(e){return Object(n.post)("/api/project_branches/delete",e).catch(s.a)}function o(e){return Object(n.post)("/api/project_pull_requests/delete",e).catch(s.a)}function l(e,t){return Object(n.post)("/api/project_branches/rename",{project:e,name:t}).catch(s.a)}function p(e,t,a){return Object(n.post)("/api/project_branches/set_automatic_deletion_protection",{project:e,branch:t,value:a}).catch(s.a)}}}]);
//# sourceMappingURL=345.m.055915d8.chunk.js.map