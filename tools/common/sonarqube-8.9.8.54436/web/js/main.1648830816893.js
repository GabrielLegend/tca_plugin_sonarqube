!function(s){function n(n){for(var t,u,i=n[0],j=n[1],c=n[2],l=n[3]||[],d=0,h=[];d<i.length;d++)u=i[d],Object.prototype.hasOwnProperty.call(r,u)&&r[u]&&h.push(r[u][0]),r[u]=0;for(t in j)Object.prototype.hasOwnProperty.call(j,t)&&(s[t]=j[t]);for(f&&f(n),a.push.apply(a,l);h.length;)h.shift()();return o.push.apply(o,c||[]),e()}function e(){for(var s,n=0;n<o.length;n++){for(var e=o[n],t=!0,j=1;j<e.length;j++){var c=e[j];0!==r[c]&&(t=!1)}t&&(o.splice(n--,1),s=i(i.s=e[0]))}return 0===o.length&&(a.forEach((function(s){if(void 0===r[s]){r[s]=null;var n=document.createElement("link");i.nc&&n.setAttribute("nonce",i.nc),n.rel="prefetch",n.as="script",n.href=u(s),document.head.appendChild(n)}})),a.length=0),s}var t={},r={264:0},o=[],a=[];function u(s){return i.p+"js/"+({262:"app",263:"docs",265:"vendors-app",266:"vendors-docs"}[s]||s)+".1648830816893.chunk.js"}function i(n){if(t[n])return t[n].exports;var e=t[n]={i:n,l:!1,exports:{}};return s[n].call(e.exports,e,e.exports,i),e.l=!0,e.exports}i.e=function(s){var n=[],e=r[s];if(0!==e)if(e)n.push(e[2]);else{var t=new Promise((function(n,t){e=r[s]=[n,t]}));n.push(e[2]=t);var o,a=document.createElement("script");a.charset="utf-8",a.timeout=120,i.nc&&a.setAttribute("nonce",i.nc),a.src=u(s);var j=new Error;o=function(n){a.onerror=a.onload=null,clearTimeout(c);var e=r[s];if(0!==e){if(e){var t=n&&("load"===n.type?"missing":n.type),o=n&&n.target&&n.target.src;j.message="Loading chunk "+s+" failed.\n("+t+": "+o+")",j.name="ChunkLoadError",j.type=t,j.request=o,e[1](j)}r[s]=void 0}};var c=setTimeout((function(){o({type:"timeout",target:a})}),12e4);a.onerror=a.onload=o,document.head.appendChild(a)}return Promise.all(n)},i.m=s,i.c=t,i.d=function(s,n,e){i.o(s,n)||Object.defineProperty(s,n,{enumerable:!0,get:e})},i.r=function(s){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(s,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(s,"__esModule",{value:!0})},i.t=function(s,n){if(1&n&&(s=i(s)),8&n)return s;if(4&n&&"object"==typeof s&&s&&s.__esModule)return s;var e=Object.create(null);if(i.r(e),Object.defineProperty(e,"default",{enumerable:!0,value:s}),2&n&&"string"!=typeof s)for(var t in s)i.d(e,t,function(n){return s[n]}.bind(null,t));return e},i.n=function(s){var n=s&&s.__esModule?function(){return s.default}:function(){return s};return i.d(n,"a",n),n},i.o=function(s,n){return Object.prototype.hasOwnProperty.call(s,n)},i.p="",i.oe=function(s){throw console.error(s),s};var j=window.webpackJsonp=window.webpackJsonp||[],c=j.push.bind(j);j.push=n,j=j.slice();for(var l=0;l<j.length;l++)n(j[l]);var f=c;o.push([430,267]),e()}({38:function(s,n,e){"use strict";var t;e.r(n),e.d(n,"getBaseUrl",(function(){return o})),e.d(n,"getSystemStatus",(function(){return a})),e.d(n,"getInstance",(function(){return u})),e.d(n,"isOfficial",(function(){return i})),e.d(n,"isSonarCloud",(function(){return j})),function(s){s.SonarQube="SonarQube",s.SonarCloud="SonarCloud"}(t||(t={}));var r=e(48);function o(){return Object(r.a)().baseUrl}function a(){return Object(r.a)().serverStatus}function u(){return Object(r.a)().instance}function i(){return Object(r.a)().official}function j(){return u()===t.SonarCloud}},430:function(s,n,e){e(431),e(635),s.exports=e(636)},431:function(s,n,e){"use strict";e.r(n);e(432),e(433),e(434),e(435),e(436),e(437),e(438),e(439),e(440),e(441),e(442),e(443),e(444),e(445),e(446),e(447),e(448),e(449),e(450),e(451),e(452),e(453),e(454),e(455),e(456),e(457),e(458),e(79),e(459),e(460),e(461),e(462),e(463),e(464),e(465),e(466),e(467),e(468),e(469),e(470),e(471),e(472),e(474),e(475),e(477),e(478),e(479),e(480),e(481),e(482),e(483),e(484),e(485),e(486),e(487),e(488),e(490),e(491),e(492),e(493),e(494),e(495),e(496),e(497),e(498),e(499),e(500),e(501),e(502),e(504),e(505),e(506),e(507),e(508),e(509),e(511),e(513),e(515),e(516),e(517),e(518),e(519),e(520),e(521),e(522),e(523),e(524),e(525),e(526),e(527),e(528),e(529),e(530),e(531),e(532),e(533),e(534),e(536),e(537),e(540),e(541),e(542),e(544),e(545),e(546),e(547),e(548),e(549),e(550),e(551),e(552),e(553),e(554),e(555),e(165),e(556),e(557),e(558),e(559),e(560),e(561),e(562),e(166),e(563),e(564),e(565),e(566),e(567),e(568),e(569),e(570),e(571),e(572),e(573),e(574),e(575),e(576),e(577),e(578),e(579),e(580),e(581),e(582),e(583),e(584),e(585),e(586),e(587),e(588),e(590),e(591),e(592),e(593),e(594),e(595),e(596),e(597),e(598),e(599),e(600),e(601),e(602),e(603),e(604),e(605),e(606),e(607),e(608),e(609),e(610),e(611),e(612),e(613),e(614),e(615),e(616),e(617),e(618),e(619),e(620),e(621),e(622),e(623),e(624),e(625),e(626),e(627),e(628),e(629),e(632),e(174),e(633),e(634)},48:function(s,n,e){"use strict";function t(){return window}e.d(n,"a",(function(){return t}))},635:function(s,n,e){"use strict";e.p=window.baseUrl+"/"},636:function(s,n,e){"use strict";e.r(n);var t,r=e(35),o=e.n(r),a=e(49),u=e(94),i=e(95),j=e(38);e(655);if(o.a.setUrlContext(Object(j.getBaseUrl)()),Object(u.d)(),t=window.location.pathname,"UP"!==Object(j.getSystemStatus)()||t.startsWith(Object(j.getBaseUrl)()+"/sessions")||t.startsWith(Object(j.getBaseUrl)()+"/maintenance")||t.startsWith(Object(j.getBaseUrl)()+"/setup")||t.startsWith(Object(j.getBaseUrl)()+"/formatting/help")){var c=new Promise((function(s){l().then((function(n){s(n)})).catch((function(){s(void 0)}))}));Promise.all([Object(i.b)(),c,f()]).then((function(s){var n=s[0],e=s[1];(0,s[2])(n.locale,void 0,e)}),(function(s){h(s)}))}else Object(u.c)(),Promise.all([Object(i.b)(),Object(a.request)("/api/users/current").submit().then(d).then(a.parseJSON),l(),f()]).then((function(s){var n=s[0],e=s[1],t=s[2];(0,s[3])(n.locale,e,t)}),(function(s){var n;!function(s){return"number"==typeof s.status}(s)||401!==s.status?h(s):(n=window.location.pathname+window.location.search+window.location.hash,window.location.href=Object(j.getBaseUrl)()+"/sessions/new?return_to="+encodeURIComponent(n))}));function l(){return Object(a.request)("/api/navigation/global").submit().then(d).then(a.parseJSON)}function f(){return Promise.all([e.e(12),e.e(265),e.e(262)]).then(e.bind(null,659)).then((function(s){return s.default}))}function d(s){return new Promise((function(n,e){s.status>=200&&s.status<300?n(s):e(s)}))}function h(s){console.error("Application failed to start!",s)}},654:function(s,n,e){var t={"./":[656,371],"./af":[185,17],"./af.js":[185,17],"./agq":[186,18],"./agq.js":[186,18],"./ak":[187,19],"./ak.js":[187,19],"./am":[188,20],"./am.js":[188,20],"./ar":[189,21],"./ar.js":[189,21],"./ars":[190,22],"./ars.js":[190,22],"./as":[191,23],"./as.js":[191,23],"./asa":[192,24],"./asa.js":[192,24],"./ast":[193,25],"./ast.js":[193,25],"./az":[194,26],"./az.js":[194,26],"./bas":[195,27],"./bas.js":[195,27],"./be":[196,28],"./be.js":[196,28],"./bem":[197,29],"./bem.js":[197,29],"./bez":[198,30],"./bez.js":[198,30],"./bg":[199,31],"./bg.js":[199,31],"./bh":[200,32],"./bh.js":[200,32],"./bm":[201,33],"./bm.js":[201,33],"./bn":[202,34],"./bn.js":[202,34],"./bo":[203,35],"./bo.js":[203,35],"./br":[204,36],"./br.js":[204,36],"./brx":[205,37],"./brx.js":[205,37],"./bs":[206,38],"./bs.js":[206,38],"./ca":[207,39],"./ca.js":[207,39],"./ccp":[208,40],"./ccp.js":[208,40],"./ce":[209,41],"./ce.js":[209,41],"./cgg":[210,42],"./cgg.js":[210,42],"./chr":[211,43],"./chr.js":[211,43],"./ckb":[212,44],"./ckb.js":[212,44],"./cs":[213,45],"./cs.js":[213,45],"./cu":[214,46],"./cu.js":[214,46],"./cy":[215,47],"./cy.js":[215,47],"./da":[216,48],"./da.js":[216,48],"./dav":[217,49],"./dav.js":[217,49],"./de":[218,50],"./de.js":[218,50],"./dje":[219,51],"./dje.js":[219,51],"./dsb":[220,52],"./dsb.js":[220,52],"./dua":[221,53],"./dua.js":[221,53],"./dv":[222,54],"./dv.js":[222,54],"./dyo":[223,55],"./dyo.js":[223,55],"./dz":[224,56],"./dz.js":[224,56],"./ebu":[225,57],"./ebu.js":[225,57],"./ee":[226,58],"./ee.js":[226,58],"./el":[227,59],"./el.js":[227,59],"./en":[228,60],"./en.js":[228,60],"./eo":[229,61],"./eo.js":[229,61],"./es":[230,62],"./es.js":[230,62],"./et":[231,63],"./et.js":[231,63],"./eu":[232,64],"./eu.js":[232,64],"./ewo":[233,65],"./ewo.js":[233,65],"./fa":[234,66],"./fa.js":[234,66],"./ff":[235,67],"./ff.js":[235,67],"./fi":[236,68],"./fi.js":[236,68],"./fil":[237,69],"./fil.js":[237,69],"./fo":[238,70],"./fo.js":[238,70],"./fr":[239,71],"./fr.js":[239,71],"./fur":[240,72],"./fur.js":[240,72],"./fy":[241,73],"./fy.js":[241,73],"./ga":[242,74],"./ga.js":[242,74],"./gd":[243,75],"./gd.js":[243,75],"./gl":[244,76],"./gl.js":[244,76],"./gsw":[245,77],"./gsw.js":[245,77],"./gu":[246,78],"./gu.js":[246,78],"./guw":[247,79],"./guw.js":[247,79],"./guz":[248,80],"./guz.js":[248,80],"./gv":[249,81],"./gv.js":[249,81],"./ha":[250,82],"./ha.js":[250,82],"./haw":[251,83],"./haw.js":[251,83],"./he":[252,84],"./he.js":[252,84],"./hi":[253,85],"./hi.js":[253,85],"./hr":[254,86],"./hr.js":[254,86],"./hsb":[255,87],"./hsb.js":[255,87],"./hu":[256,88],"./hu.js":[256,88],"./hy":[257,89],"./hy.js":[257,89],"./ia":[258,90],"./ia.js":[258,90],"./id":[259,91],"./id.js":[259,91],"./ig":[260,92],"./ig.js":[260,92],"./ii":[261,93],"./ii.js":[261,93],"./in":[262,94],"./in.js":[262,94],"./index":[657,372],"./index.js":[658,373],"./io":[263,95],"./io.js":[263,95],"./is":[264,96],"./is.js":[264,96],"./it":[265,97],"./it.js":[265,97],"./iu":[266,98],"./iu.js":[266,98],"./iw":[267,99],"./iw.js":[267,99],"./ja":[268,100],"./ja.js":[268,100],"./jbo":[269,101],"./jbo.js":[269,101],"./jgo":[270,102],"./jgo.js":[270,102],"./ji":[271,103],"./ji.js":[271,103],"./jmc":[272,104],"./jmc.js":[272,104],"./jv":[273,105],"./jv.js":[273,105],"./jw":[274,106],"./jw.js":[274,106],"./ka":[275,107],"./ka.js":[275,107],"./kab":[276,108],"./kab.js":[276,108],"./kaj":[277,109],"./kaj.js":[277,109],"./kam":[278,110],"./kam.js":[278,110],"./kcg":[279,111],"./kcg.js":[279,111],"./kde":[280,112],"./kde.js":[280,112],"./kea":[281,113],"./kea.js":[281,113],"./khq":[282,114],"./khq.js":[282,114],"./ki":[283,115],"./ki.js":[283,115],"./kk":[284,116],"./kk.js":[284,116],"./kkj":[285,117],"./kkj.js":[285,117],"./kl":[286,118],"./kl.js":[286,118],"./kln":[287,119],"./kln.js":[287,119],"./km":[288,120],"./km.js":[288,120],"./kn":[289,121],"./kn.js":[289,121],"./ko":[290,122],"./ko.js":[290,122],"./kok":[291,123],"./kok.js":[291,123],"./ks":[292,124],"./ks.js":[292,124],"./ksb":[293,125],"./ksb.js":[293,125],"./ksf":[294,126],"./ksf.js":[294,126],"./ksh":[295,127],"./ksh.js":[295,127],"./ku":[296,128],"./ku.js":[296,128],"./kw":[297,129],"./kw.js":[297,129],"./ky":[298,130],"./ky.js":[298,130],"./lag":[299,131],"./lag.js":[299,131],"./lb":[300,132],"./lb.js":[300,132],"./lg":[301,133],"./lg.js":[301,133],"./lkt":[302,134],"./lkt.js":[302,134],"./ln":[303,135],"./ln.js":[303,135],"./lo":[304,136],"./lo.js":[304,136],"./lrc":[305,137],"./lrc.js":[305,137],"./lt":[306,138],"./lt.js":[306,138],"./lu":[307,139],"./lu.js":[307,139],"./luo":[308,140],"./luo.js":[308,140],"./luy":[309,141],"./luy.js":[309,141],"./lv":[310,142],"./lv.js":[310,142],"./mas":[311,143],"./mas.js":[311,143],"./mer":[312,144],"./mer.js":[312,144],"./mfe":[313,145],"./mfe.js":[313,145],"./mg":[314,146],"./mg.js":[314,146],"./mgh":[315,147],"./mgh.js":[315,147],"./mgo":[316,148],"./mgo.js":[316,148],"./mi":[317,149],"./mi.js":[317,149],"./mk":[318,150],"./mk.js":[318,150],"./ml":[319,151],"./ml.js":[319,151],"./mn":[320,152],"./mn.js":[320,152],"./mo":[321,153],"./mo.js":[321,153],"./mr":[322,154],"./mr.js":[322,154],"./ms":[323,155],"./ms.js":[323,155],"./mt":[324,156],"./mt.js":[324,156],"./mua":[325,157],"./mua.js":[325,157],"./my":[326,158],"./my.js":[326,158],"./mzn":[327,159],"./mzn.js":[327,159],"./nah":[328,160],"./nah.js":[328,160],"./naq":[329,161],"./naq.js":[329,161],"./nb":[330,162],"./nb.js":[330,162],"./nd":[331,163],"./nd.js":[331,163],"./nds":[332,164],"./nds.js":[332,164],"./ne":[333,165],"./ne.js":[333,165],"./nl":[334,166],"./nl.js":[334,166],"./nmg":[335,167],"./nmg.js":[335,167],"./nn":[336,168],"./nn.js":[336,168],"./nnh":[337,169],"./nnh.js":[337,169],"./no":[338,170],"./no.js":[338,170],"./nqo":[339,171],"./nqo.js":[339,171],"./nr":[340,172],"./nr.js":[340,172],"./nso":[341,173],"./nso.js":[341,173],"./nus":[342,174],"./nus.js":[342,174],"./ny":[343,175],"./ny.js":[343,175],"./nyn":[344,176],"./nyn.js":[344,176],"./om":[345,177],"./om.js":[345,177],"./or":[346,178],"./or.js":[346,178],"./os":[347,179],"./os.js":[347,179],"./pa":[348,180],"./pa.js":[348,180],"./pap":[349,181],"./pap.js":[349,181],"./pl":[350,182],"./pl.js":[350,182],"./prg":[351,183],"./prg.js":[351,183],"./ps":[352,184],"./ps.js":[352,184],"./pt":[353,185],"./pt.js":[353,185],"./qu":[354,186],"./qu.js":[354,186],"./rm":[355,187],"./rm.js":[355,187],"./rn":[356,188],"./rn.js":[356,188],"./ro":[357,189],"./ro.js":[357,189],"./rof":[358,190],"./rof.js":[358,190],"./ru":[359,191],"./ru.js":[359,191],"./rw":[360,192],"./rw.js":[360,192],"./rwk":[361,193],"./rwk.js":[361,193],"./sah":[362,194],"./sah.js":[362,194],"./saq":[363,195],"./saq.js":[363,195],"./sbp":[364,196],"./sbp.js":[364,196],"./sc":[365,197],"./sc.js":[365,197],"./scn":[366,198],"./scn.js":[366,198],"./sd":[367,199],"./sd.js":[367,199],"./sdh":[368,200],"./sdh.js":[368,200],"./se":[369,201],"./se.js":[369,201],"./seh":[370,202],"./seh.js":[370,202],"./ses":[371,203],"./ses.js":[371,203],"./sg":[372,204],"./sg.js":[372,204],"./sh":[373,205],"./sh.js":[373,205],"./shi":[374,206],"./shi.js":[374,206],"./si":[375,207],"./si.js":[375,207],"./sk":[376,208],"./sk.js":[376,208],"./sl":[377,209],"./sl.js":[377,209],"./sma":[378,210],"./sma.js":[378,210],"./smi":[379,211],"./smi.js":[379,211],"./smj":[380,212],"./smj.js":[380,212],"./smn":[381,213],"./smn.js":[381,213],"./sms":[382,214],"./sms.js":[382,214],"./sn":[383,215],"./sn.js":[383,215],"./so":[384,216],"./so.js":[384,216],"./sq":[385,217],"./sq.js":[385,217],"./sr":[386,218],"./sr.js":[386,218],"./ss":[387,219],"./ss.js":[387,219],"./ssy":[388,220],"./ssy.js":[388,220],"./st":[389,221],"./st.js":[389,221],"./sv":[390,222],"./sv.js":[390,222],"./sw":[391,223],"./sw.js":[391,223],"./syr":[392,224],"./syr.js":[392,224],"./ta":[393,225],"./ta.js":[393,225],"./te":[394,226],"./te.js":[394,226],"./teo":[395,227],"./teo.js":[395,227],"./tg":[396,228],"./tg.js":[396,228],"./th":[397,229],"./th.js":[397,229],"./ti":[398,230],"./ti.js":[398,230],"./tig":[399,231],"./tig.js":[399,231],"./tk":[400,232],"./tk.js":[400,232],"./tl":[401,233],"./tl.js":[401,233],"./tn":[402,234],"./tn.js":[402,234],"./to":[403,235],"./to.js":[403,235],"./tr":[404,236],"./tr.js":[404,236],"./ts":[405,237],"./ts.js":[405,237],"./tt":[406,238],"./tt.js":[406,238],"./twq":[407,239],"./twq.js":[407,239],"./tzm":[408,240],"./tzm.js":[408,240],"./ug":[409,241],"./ug.js":[409,241],"./uk":[410,242],"./uk.js":[410,242],"./ur":[411,243],"./ur.js":[411,243],"./uz":[412,244],"./uz.js":[412,244],"./vai":[413,245],"./vai.js":[413,245],"./ve":[414,246],"./ve.js":[414,246],"./vi":[415,247],"./vi.js":[415,247],"./vo":[416,248],"./vo.js":[416,248],"./vun":[417,249],"./vun.js":[417,249],"./wa":[418,250],"./wa.js":[418,250],"./wae":[419,251],"./wae.js":[419,251],"./wo":[420,252],"./wo.js":[420,252],"./xh":[421,253],"./xh.js":[421,253],"./xog":[422,254],"./xog.js":[422,254],"./yav":[423,255],"./yav.js":[423,255],"./yi":[424,256],"./yi.js":[424,256],"./yo":[425,257],"./yo.js":[425,257],"./yue":[426,258],"./yue.js":[426,258],"./zgh":[427,259],"./zgh.js":[427,259],"./zh":[428,260],"./zh.js":[428,260],"./zu":[429,261],"./zu.js":[429,261]};function r(s){if(!e.o(t,s))return Promise.resolve().then((function(){var n=new Error("Cannot find module '"+s+"'");throw n.code="MODULE_NOT_FOUND",n}));var n=t[s],r=n[0];return e.e(n[1]).then((function(){return e.t(r,7)}))}r.keys=function(){return Object.keys(t)},r.id=654,s.exports=r},655:function(s,n,e){},94:function(s,n,e){"use strict";e.d(n,"c",(function(){return u})),e.d(n,"d",(function(){return i})),e.d(n,"a",(function(){return j})),e.d(n,"b",(function(){return c}));var t=e(48),r={};function o(s,n){r[s]=n}function a(s){o("sq-web-analytics",s)}function u(){Object(t.a)().registerExtension=o}function i(){Object(t.a)().setWebAnalyticsPageChangeHandler=a}function j(s){return r[s]}function c(){return r["sq-web-analytics"]}},95:function(s,n,e){"use strict";e.d(n,"b",(function(){return l})),e.d(n,"a",(function(){return d}));var t=e(129),r=e(35),o=e.n(r),a=e(93),u=e(49);function i(s){return Object(u.getJSON)("/api/l10n/index",s)}var j=function(s,n,e,t){return new(e||(e=Promise))((function(r,o){function a(s){try{i(t.next(s))}catch(s){o(s)}}function u(s){try{i(t.throw(s))}catch(s){o(s)}}function i(s){var n;s.done?r(s.value):(n=s.value,n instanceof e?n:new e((function(s){s(n)}))).then(a,u)}i((t=t.apply(s,n||[])).next())}))},c=function(s,n){var e,t,r,o,a={label:0,sent:function(){if(1&r[0])throw r[1];return r[1]},trys:[],ops:[]};return o={next:u(0),throw:u(1),return:u(2)},"function"==typeof Symbol&&(o[Symbol.iterator]=function(){return this}),o;function u(o){return function(u){return function(o){if(e)throw new TypeError("Generator is already executing.");for(;a;)try{if(e=1,t&&(r=2&o[0]?t.return:o[0]?t.throw||((r=t.return)&&r.call(t),0):t.next)&&!(r=r.call(t,o[1])).done)return r;switch(t=0,r&&(o=[2&o[0],r.value]),o[0]){case 0:case 1:r=o;break;case 4:return a.label++,{value:o[1],done:!1};case 5:a.label++,t=o[1],o=[0];continue;case 7:o=a.ops.pop(),a.trys.pop();continue;default:if(!(r=(r=a.trys).length>0&&r[r.length-1])&&(6===o[0]||2===o[0])){a=0;continue}if(3===o[0]&&(!r||o[1]>r[0]&&o[1]<r[3])){a.label=o[1];break}if(6===o[0]&&a.label<r[1]){a.label=r[1],r=o;break}if(r&&a.label<r[2]){a.label=r[2],a.ops.push(o);break}r[2]&&a.ops.pop(),a.trys.pop();continue}o=n.call(s,a)}catch(s){o=[6,s],t=0}finally{e=r=0}if(5&o[0])throw o[1];return{value:o[0]?o[1]:void 0,done:!0}}([o,u])}}};function l(){return j(this,void 0,void 0,(function(){var s,n,t;return c(this,(function(a){switch(a.label){case 0:return[4,f().catch((function(){return{locale:r.DEFAULT_LOCALE,messages:{}}}))];case 1:return s=a.sent(),o.a.setLocale(s.locale).setMessages(s.messages),s.locale===r.DEFAULT_LOCALE?[3,3]:[4,Promise.all([e(654)("./"+s.locale),Promise.all([e.e(12),e.e(355)]).then(e.bind(null,665))])];case 2:n=a.sent(),t=n[0],n[1].addLocaleData(t.default),a.label=3;case 3:return[2,s]}}))}))}function f(){return j(this,void 0,void 0,(function(){var s,n,e,o,u,j,l;return c(this,(function(c){switch(c.label){case 0:return s=window.navigator.languages?window.navigator.languages[0]:window.navigator.language,n=h(),e={},s&&(e.locale=s,n.locale&&s.startsWith(n.locale)&&n.timestamp&&n.messages&&(e.ts=n.timestamp)),[4,i(e).catch((function(e){var t;if(e&&304===e.status)return{effectiveLocale:n.locale||s||r.DEFAULT_LOCALE,messages:null!==(t=n.messages)&&void 0!==t?t:{}};throw new Error("Unexpected status code: "+e.status)}))];case 1:return o=c.sent(),u=o.effectiveLocale,j=o.messages,function(s){Object(a.save)("l10n.bundle",JSON.stringify(s))}(l={timestamp:Object(t.toNotSoISOString)(new Date),locale:u,messages:j}),[2,l]}}))}))}function d(){return h()}function h(){var s,n;try{n=JSON.parse(null!==(s=Object(a.get)("l10n.bundle"))&&void 0!==s?s:"{}")}catch(s){n={}}return n}}});
//# sourceMappingURL=main.1648830816893.js.map